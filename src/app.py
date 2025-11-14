import os, datetime, bleach, uuid, json
from flask import Flask, render_template, redirect, url_for, request, flash, abort, Blueprint, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.csrf import generate_csrf
from flask_wtf.file import FileField, FileAllowed
from werkzeug.utils import secure_filename
from wtforms import StringField, PasswordField, SelectField, TextAreaField, DateTimeLocalField
from wtforms.validators import InputRequired, Email, Length, Optional
from passlib.hash import bcrypt
from ics import Calendar, Event
from io import BytesIO
from PIL import Image
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
from .data_access import (
    get_distinct_locations_published,
    get_category_counts_published,
    get_booking_trend_counts,
    get_inbox_threads,
    get_hourly_bookings,
)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY','dev-key')
DB_PATH = os.environ.get('DATABASE_URL') or ('sqlite:///' + os.path.join(os.getcwd(), 'campus.db').replace('\\','/'))
app.config['SQLALCHEMY_DATABASE_URI'] = DB_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_TIME_LIMIT'] = 3600
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'img', 'uploads')

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app, session_options={"expire_on_commit": False})
login_manager = LoginManager(app)
login_manager.login_view = 'auth.login'
CSRFProtect(app)  # CSRF on all POST

# Basic rate limiting (IP-based). For production, configure a shared store.
limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")

# Make CSRF token available in all templates
@app.context_processor
def inject_csrf_token():
    def get_csrf_token():
        return generate_csrf()
    return dict(csrf_token=get_csrf_token)

@app.context_processor
def inject_template_flags():
    return dict(include_scripts=not app.config.get('TESTING', False))

# Security headers (CSP, etc.)
@app.after_request
def set_security_headers(resp):
    csp = " ".join([
        "default-src 'self'",
        "script-src 'self' https://cdn.jsdelivr.net",
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
        "img-src 'self' data: https:",
        "connect-src 'self' https://cdn.jsdelivr.net",
        "object-src 'none'",
        "frame-ancestors 'self'",
        "base-uri 'self'",
        "form-action 'self'",
    ])
    resp.headers.setdefault('Content-Security-Policy', csp)
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    return resp

class User(db.Model, UserMixin):
    __tablename__='users'
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student')
    department = db.Column(db.String(120))
    is_approved = db.Column(db.Boolean, default=False)
    request_admin = db.Column(db.Boolean, default=False)
    notif_email_updates = db.Column(db.Boolean, default=True)
    notif_booking_alerts = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    def get_id(self): return str(self.user_id)

class Resource(db.Model):
    __tablename__='resources'
    resource_id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    title = db.Column(db.String(120))
    description = db.Column(db.Text)
    category = db.Column(db.String(60))
    location = db.Column(db.String(120))
    capacity = db.Column(db.Integer, default=1)
    images = db.Column(db.Text)
    availability_rules = db.Column(db.Text)
    status = db.Column(db.String(20), default='draft')
    restriction = db.Column(db.String(20), default='open')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    @property
    def image_url(self):
        if self.images:
            return self.images.split(',')[0]
        return '/static/img/1.png'

class Booking(db.Model):
    __tablename__='bookings'
    booking_id = db.Column(db.Integer, primary_key=True)
    resource_id = db.Column(db.Integer, db.ForeignKey('resources.resource_id'))
    requester_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    start_datetime = db.Column(db.DateTime)
    end_datetime = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    resource = db.relationship('Resource')
    requester = db.relationship('User')

class Review(db.Model):
    __tablename__='reviews'
    review_id = db.Column(db.Integer, primary_key=True)
    resource_id = db.Column(db.Integer, db.ForeignKey('resources.resource_id'))
    reviewer_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    rating = db.Column(db.Integer)
    comment = db.Column(db.Text)
    flagged = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    reviewer = db.relationship('User')
    resource = db.relationship('Resource')

class Message(db.Model):
    __tablename__='messages'
    message_id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Notification(db.Model):
    __tablename__='notifications'
    notification_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    content = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    read = db.Column(db.Boolean, default=False)

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=2)])

class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), Length(min=2, max=120)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=2)])
    role = SelectField('Role', choices=[('student','Student'),('staff','Staff')])

class BookingForm(FlaskForm):
    start_datetime = DateTimeLocalField('Start', format='%Y-%m-%dT%H:%M')
    end_datetime = DateTimeLocalField('End', format='%Y-%m-%dT%H:%M')

class ProfileForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), Length(min=2, max=120)])
    email = StringField('Email', validators=[InputRequired(), Email()])

class ReviewForm(FlaskForm):
    rating = SelectField('Rating', choices=[('5','5'),('4','4'),('3','3'),('2','2'),('1','1')], validators=[InputRequired()])
    comment = StringField('Comment', validators=[Length(max=500)])


class PasswordForm(FlaskForm):
    current = PasswordField('Current', validators=[InputRequired(), Length(min=2)])
    new = PasswordField('New', validators=[InputRequired(), Length(min=2)])
    confirm = PasswordField('Confirm', validators=[InputRequired(), Length(min=2)])

class NotificationsForm(FlaskForm):
    email_updates = SelectField('Email', choices=[('y','On'),('n','Off')], coerce=str)
    booking_alerts = SelectField('Booking', choices=[('y','On'),('n','Off')], coerce=str)

class ResourceForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired(), Length(min=2, max=120)])
    description = TextAreaField('Description', validators=[Length(max=1000)])
    category = SelectField('Category', choices=[('Classroom','Classroom'),('Conference Room','Conference Room'),('Lab','Lab'),('Equipment','Equipment')], validators=[InputRequired()])
    location = StringField('Location', validators=[InputRequired(), Length(max=120)])
    capacity = StringField('Capacity', validators=[InputRequired()])
    restriction = SelectField('Restriction', choices=[('open','Open'),('restricted','Restricted')], default='open')
    image_file = FileField('Upload Image', validators=[Optional(), FileAllowed(['jpg', 'jpeg', 'png', 'gif', 'webp'], 'Images only!')])
    images = StringField('Image URLs (optional: comma-separated or Google Drive links)', validators=[Optional(), Length(max=500)])
    availability_rules = TextAreaField('Availability Rules', validators=[Length(max=500)])

# Admin: manage users
class AdminUserForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), Length(min=2, max=120)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    role = SelectField('Role', choices=[('student','Student'),('staff','Staff'),('admin','Admin')], validators=[InputRequired()])
    department = StringField('Department', validators=[Optional(), Length(max=120)])
    is_approved = SelectField('Approved', choices=[('y','Yes'),('n','No')], validators=[InputRequired()])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def parse_slot(date_str, slot):
    start_h, end_h = slot.split('-')
    start = datetime.datetime.strptime(date_str+' '+start_h, "%Y-%m-%d %H:%M")
    end = datetime.datetime.strptime(date_str+' '+end_h, "%Y-%m-%d %H:%M")
    return start, end

SLOTS = ['08:00-09:00','09:00-10:00','10:00-11:00','11:00-12:00','13:00-14:00','14:00-15:00','15:00-16:00']

def busy_slots(resource_id, date):
    busy=set()
    day_start = datetime.datetime.combine(date, datetime.time.min)
    day_end = datetime.datetime.combine(date, datetime.time.max)
    bs = Booking.query.filter_by(resource_id=resource_id).filter(Booking.status.in_(['pending','approved'])).filter(Booking.start_datetime>=day_start, Booking.end_datetime<=day_end).all()
    for b in bs:
        for s in SLOTS:
            st, en = parse_slot(date.strftime("%Y-%m-%d"), s)
            if not (en <= b.start_datetime or st >= b.end_datetime):
                busy.add(s)
    return busy

def available_slots(resource_id, date):
    if not date: return SLOTS
    taken = busy_slots(resource_id, date)
    return [s for s in SLOTS if s not in taken]

def notify(user_id, text):
    n = Notification(user_id=user_id, content=text); db.session.add(n); db.session.commit()

def process_and_crop_image(image_file, target_width=800, target_height=450):
    """
    Process uploaded image: crop to 16:9 aspect ratio and resize to target dimensions.
    Returns the saved file path relative to static folder.
    """
    try:
        # Open and process image
        img = Image.open(image_file)
        img_format = img.format or 'JPEG'
        
        # Convert RGBA to RGB if necessary
        if img.mode in ('RGBA', 'LA', 'P'):
            background = Image.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'P':
                img = img.convert('RGBA')
            background.paste(img, mask=img.split()[-1] if img.mode in ('RGBA', 'LA') else None)
            img = background
        elif img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Get current dimensions
        width, height = img.size
        target_ratio = target_width / target_height  # 16:9 = 1.777...
        
        # Calculate crop dimensions to maintain aspect ratio
        current_ratio = width / height
        
        if current_ratio > target_ratio:
            # Image is wider than target - crop width
            new_width = int(height * target_ratio)
            left = (width - new_width) // 2
            crop_box = (left, 0, left + new_width, height)
        else:
            # Image is taller than target - crop height
            new_height = int(width / target_ratio)
            top = (height - new_height) // 2
            crop_box = (0, top, width, top + new_height)
        
        # Crop image
        img_cropped = img.crop(crop_box)
        
        # Resize to target dimensions
        img_resized = img_cropped.resize((target_width, target_height), Image.Resampling.LANCZOS)
        
        # Generate unique filename
        filename = f"{uuid.uuid4().hex}.jpg"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Save with quality optimization
        img_resized.save(filepath, 'JPEG', quality=85, optimize=True)
        
        # Return relative path for URL
        return f"/static/img/uploads/{filename}"
    except Exception as e:
        raise Exception(f"Error processing image: {str(e)}")

main_bp = Blueprint('main', __name__)
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
resources_bp = Blueprint('resources', __name__, url_prefix='/resources')
bookings_bp = Blueprint('bookings', __name__, url_prefix='/bookings')
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
users_bp = Blueprint('users', __name__, url_prefix='/users')
messages_bp = Blueprint('messages', __name__, url_prefix='/messages')
reports_bp = Blueprint('reports', __name__, url_prefix='/reports')
api_bp = Blueprint('api', __name__, url_prefix='/api')

@main_bp.route('/')
def home():
    # Fetch published resources
    resources = Resource.query.filter_by(status='published').all()

    # Enrich with aggregate fields used for sorting
    enriched = []
    for r in resources:
        booked = Booking.query.filter_by(resource_id=r.resource_id).count()
        rv = Review.query.filter_by(resource_id=r.resource_id, flagged=False).all()
        avg = (sum(x.rating for x in rv)/len(rv)) if rv else 0
        r.booked_count = booked
        r.avg = avg
        enriched.append(r)

    # Apply sort based on query param
    sort = request.args.get('sort', 'recent')
    sort_label = {'recent': 'Recent', 'booked': 'Most booked', 'rated': 'Top rated'}.get(sort, 'Recent')
    if sort == 'booked':
        enriched.sort(key=lambda x: x.booked_count or 0, reverse=True)
    elif sort == 'rated':
        enriched.sort(key=lambda x: x.avg or 0, reverse=True)
    else:
        enriched.sort(key=lambda x: x.created_at, reverse=True)

    total = len(enriched)
    rows = enriched[:4]

    return render_template('home.html', top=rows, show_more=(total > 4), sort=sort, sort_label=sort_label)

@resources_bp.route('/')
def browse():
    q = Resource.query.filter_by(status='published')
    if request.args.get('q'):
        term = f"%{request.args['q']}%"
        q = q.filter(db.or_(Resource.title.ilike(term), Resource.description.ilike(term)))
    if request.args.get('category'):
        q = q.filter_by(category=request.args['category'])
    if request.args.get('location'):
        q = q.filter_by(location=request.args['location'])
    if request.args.get('capacity'):
        try: q = q.filter(Resource.capacity >= int(request.args['capacity']))
        except: pass

    resources = q.all()

    date_str = request.args.get('date') or ''
    slot = request.args.get('slot') or ''
    filter_by_slot=False
    if date_str:
        try:
            d = datetime.datetime.strptime(date_str, "%Y-%m-%d").date()
            if slot:
                st,en = parse_slot(date_str, slot); filter_by_slot=True
        except: d=None
    else: d=None

    enriched=[]
    for r in resources:
        booked = Booking.query.filter_by(resource_id=r.resource_id).count()
        rv = Review.query.filter_by(resource_id=r.resource_id, flagged=False).all()
        avg = (sum(x.rating for x in rv)/len(rv)) if rv else 0
        r.booked_count = booked; r.avg=avg
        include=True
        if d:
            free = available_slots(r.resource_id, d)
            if filter_by_slot:
                include = slot in free
            else:
                include = len(free)>0
        if include:
            enriched.append(r)

    sort = request.args.get('sort','recent')
    sort_label = {'recent':'Recent','booked':'Most booked','rated':'Top rated'}.get(sort,'Recent')
    if sort=='booked':
        enriched.sort(key=lambda x: x.booked_count or 0, reverse=True)
    elif sort=='rated':
        enriched.sort(key=lambda x: x.avg or 0, reverse=True)
    else:
        enriched.sort(key=lambda x: x.created_at, reverse=True)

    # Build dynamic location list for filters from published resources (via DAL)
    locations = get_distinct_locations_published(db)

    return render_template('resources_browse.html', resources=enriched, sort_label=sort_label, locations=locations)

@resources_bp.route('/<int:resource_id>')
def detail(resource_id):
    r = Resource.query.get_or_404(resource_id)
    if r.status != 'published' and (not current_user.is_authenticated or current_user.role!='admin'):
        abort(403)
    reviews = Review.query.filter_by(resource_id=resource_id, flagged=False).order_by(Review.timestamp.desc()).all()
    avg = (sum(rv.rating for rv in reviews)/len(reviews)) if reviews else 0
    date_str = request.args.get('date') or datetime.date.today().strftime("%Y-%m-%d")
    try: d = datetime.datetime.strptime(date_str, "%Y-%m-%d").date()
    except: d = datetime.date.today()
    free = available_slots(resource_id, d)
    form = BookingForm()
    review_form = ReviewForm()
    last_booking = None
    if current_user.is_authenticated:
        last_booking = Booking.query.filter_by(requester_id=current_user.user_id).order_by(Booking.created_at.desc()).first()
    return render_template('resource_detail.html', resource=r, reviews=reviews, form=form, review_form=review_form, avg_rating=avg, available_slots=free, date=date_str, conflict_warning=None, last_booking=last_booking)

@resources_bp.route('/<int:resource_id>/reviews', methods=['POST'])
@login_required
def add_review(resource_id):
    r = Resource.query.get_or_404(resource_id)
    form = ReviewForm()
    if form.validate_on_submit():
        now = datetime.datetime.utcnow()
        prior = Booking.query.filter_by(resource_id=resource_id, requester_id=current_user.user_id, status='approved').filter(Booking.end_datetime < now).first()
        if not prior:
            flash('You can only review after a completed approved booking.','warning')
            return redirect(url_for('resources.detail', resource_id=resource_id))
        comment = bleach.clean(form.comment.data or '', strip=True)
        rv = Review(resource_id=resource_id, reviewer_id=current_user.user_id, rating=int(form.rating.data), comment=comment)
        db.session.add(rv); db.session.commit()
        flash('Review submitted.','success')
    else:
        flash('Invalid review.','danger')
    return redirect(url_for('resources.detail', resource_id=resource_id))


@resources_bp.route('/<int:resource_id>/reviews/<int:review_id>/flag', methods=['POST'])
@login_required
def flag_review(resource_id, review_id):
    r = Resource.query.get_or_404(resource_id)
    rv = Review.query.filter_by(review_id=review_id, resource_id=resource_id).first_or_404()
    rv.flagged = True
    db.session.commit()
    flash('Review reported for admin review.','info')
    return redirect(url_for('resources.detail', resource_id=r.resource_id))

@bookings_bp.route('/request/<int:resource_id>', methods=['POST'])
@login_required
def request_booking(resource_id):
    r = Resource.query.get_or_404(resource_id)
    date_str = request.form.get('date'); slot = request.form.get('slot')
    if not (date_str and slot):
        flash('Please choose a date and time slot.','danger'); return redirect(url_for('resources.detail', resource_id=resource_id))
    try:
        start, end = parse_slot(date_str, slot)
    except Exception:
        flash('Invalid time slot.','danger'); return redirect(url_for('resources.detail', resource_id=resource_id))
    # Server-side date validation: future-only, coherent range, and not too far out
    now = datetime.datetime.utcnow()
    if end <= start:
        flash('End time must be after start time.','danger'); return redirect(url_for('resources.detail', resource_id=resource_id))
    if start.date() < now.date():
        flash('Cannot book for past dates.','danger'); return redirect(url_for('resources.detail', resource_id=resource_id))
    if start.date() > (now.date() + datetime.timedelta(days=365)):
        flash('Bookings cannot be more than 365 days in advance.','danger'); return redirect(url_for('resources.detail', resource_id=resource_id))
    status = 'pending'
    if slot not in available_slots(resource_id, start.date()):
        status = 'waitlisted'
        flash('Slot currently booked. You were added to the waitlist.','warning')
    else:
        if r.restriction=='open':
            status='approved'
            flash('Booking confirmed.','success')
            notify(current_user.user_id, f"Booking confirmed for {r.title} on {date_str} {slot}")
        else:
            status='pending'
            flash('Booking request submitted for admin approval.','info')
    b = Booking(resource_id=resource_id, requester_id=current_user.user_id, start_datetime=start, end_datetime=end, status=status)
    db.session.add(b); db.session.commit()
    return redirect(url_for('bookings.my_bookings'))

@bookings_bp.route('/my')
@login_required
def my_bookings():
    items = Booking.query.filter_by(requester_id=current_user.user_id).order_by(Booking.start_datetime.desc()).all()
    return render_template('my_bookings.html', bookings=items)

@bookings_bp.route('/ics/<int:booking_id>')
@login_required
def export_ics(booking_id):
    b = Booking.query.get_or_404(booking_id)
    if b.requester_id != current_user.user_id and current_user.role!='admin':
        abort(403)
    cal = Calendar()
    e = Event()
    e.name = f"Booking: {b.resource.title}"
    e.begin = b.start_datetime
    e.end = b.end_datetime
    e.location = b.resource.location or "Campus"
    cal.events.add(e)
    buf = BytesIO(); buf.write(str(cal).encode('utf-8')); buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=f"booking_{booking_id}.ics", mimetype="text/calendar")

@admin_bp.route('/')
@login_required
def dashboard():
    if current_user.role not in ['admin','staff']:
        abort(403)
    # Stats should reflect active (published) resources
    stats = dict(
        users=User.query.count(),
        resources=Resource.query.filter_by(status='published').count(),
        bookings=Booking.query.count(),
        pending_users=User.query.filter_by(is_approved=False).count(),
        approved_bookings=Booking.query.filter_by(status='approved').count(),
        pending_bookings_count=Booking.query.filter_by(status='pending').count(),
    )
    pending_bookings = Booking.query.filter_by(status='pending').order_by(Booking.created_at.desc()).all()
    pending_users = User.query.filter_by(is_approved=False).all()
    flagged_reviews = Review.query.filter_by(flagged=True).all()
    # Draft resources awaiting publication
    draft_resources = Resource.query.filter_by(status='draft').order_by(Resource.created_at.desc()).all()
    
    # Category chart data (only published resources) via DAL
    category_rows = get_category_counts_published(db)
    category_chart = {'labels':[r[0] for r in category_rows], 'values':[r[1] for r in category_rows]}
    
    # Daily trends (last 30 days)
    today = datetime.date.today()
    start_day = today - datetime.timedelta(days=29)
    rows = get_booking_trend_counts(db, start_day, today)
    counts = {d:0 for d in [(start_day + datetime.timedelta(days=i)).strftime('%Y-%m-%d') for i in range(30)]}
    for d,c in rows:
        counts[d] = c
    trend_chart = {'labels': list(counts.keys()), 'values': list(counts.values())}
    default_trend_date = today.strftime('%Y-%m-%d')
    
    return render_template('admin_dashboard.html', stats=stats, pending_bookings=pending_bookings, pending_users=pending_users, flagged_reviews=flagged_reviews, draft_resources=draft_resources, category_chart=category_chart, trend_chart=trend_chart, default_trend_date=default_trend_date)

@admin_bp.route('/bookings/<int:booking_id>/<action>')
@login_required
def approve_booking(booking_id, action):
    if current_user.role not in ['admin','staff']:
        abort(403)
    b = Booking.query.get_or_404(booking_id)
    if action=='approve':
        b.status='approved'
        notify(b.requester_id, f"Booking approved for {b.resource.title}")
    else:
        b.status='rejected'
        notify(b.requester_id, f"Booking rejected for {b.resource.title}")
        same_slot = Booking.query.filter_by(resource_id=b.resource_id, status='waitlisted', start_datetime=b.start_datetime, end_datetime=b.end_datetime).order_by(Booking.created_at.asc()).first()
        if same_slot:
            same_slot.status='approved'
            notify(same_slot.requester_id, f"Waitlist promoted for {same_slot.resource.title}")
    db.session.commit()
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/users/<int:user_id>/<action>')
@login_required
def approve_user(user_id, action):
    if current_user.role not in ['admin','staff']:
        abort(403)
    u = User.query.get_or_404(user_id)
    if action=='approve':
        u.is_approved = True
        notify(u.user_id, "Your account has been approved.")
    else:
        db.session.delete(u)
    db.session.commit()
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/users/grant-admin/<int:user_id>')
@login_required
def grant_admin(user_id):
    if current_user.role not in ['admin','staff']:
        abort(403)
    u = User.query.get_or_404(user_id)
    u.role='admin'; u.is_approved=True; u.request_admin=False
    db.session.commit()
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/users', methods=['GET'])
@login_required
def users():
    if current_user.role not in ['admin','staff']:
        abort(403)
    q = request.args.get('q','').strip().lower()
    rows = User.query
    if q:
        like = f"%{q}%"
        rows = rows.filter(db.or_(User.name.ilike(like), User.email.ilike(like), User.role.ilike(like)))
    rows = rows.order_by(User.created_at.desc()).all()
    return render_template('admin_users.html', users=rows, q=q)

@admin_bp.route('/users/<int:user_id>/edit', methods=['GET','POST'])
@login_required
def edit_user(user_id):
    if current_user.role not in ['admin','staff']:
        abort(403)
    u = User.query.get_or_404(user_id)
    form = AdminUserForm(obj=u)
    if form.validate_on_submit():
        # Email uniqueness check
        new_email = form.email.data.lower()
        other = User.query.filter_by(email=new_email).first()
        if other and other.user_id != u.user_id:
            flash('Email already in use by another account.','danger')
            return render_template('admin_edit_user.html', form=form, user=u)
        u.name = form.name.data
        u.email = new_email
        u.role = form.role.data
        u.department = (form.department.data or None)
        u.is_approved = (form.is_approved.data == 'y')
        db.session.commit()
        flash('User updated.','success')
        return redirect(url_for('admin.users'))
    # Normalize select value
    form.is_approved.data = 'y' if u.is_approved else 'n'
    return render_template('admin_edit_user.html', form=form, user=u)

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role not in ['admin','staff']:
        abort(403)
    u = User.query.get_or_404(user_id)
    # Clean up related data (messages, bookings, reviews, resources)
    Message.query.filter(db.or_(Message.sender_id==user_id, Message.receiver_id==user_id)).delete()
    Booking.query.filter_by(requester_id=user_id).delete()
    Review.query.filter_by(reviewer_id=user_id).delete()
    # Delete resources owned by the user along with their bookings/reviews
    owned = Resource.query.filter_by(owner_id=user_id).all()
    for r in owned:
        Booking.query.filter_by(resource_id=r.resource_id).delete()
        Review.query.filter_by(resource_id=r.resource_id).delete()
        db.session.delete(r)
    db.session.delete(u)
    db.session.commit()
    flash('User deleted.','success')
    return redirect(url_for('admin.users'))

@admin_bp.route('/reviews/<int:review_id>/<action>')
@login_required
def review_action(review_id, action):
    if current_user.role not in ['admin','staff']:
        abort(403)
    rv = Review.query.get_or_404(review_id)
    if action=='remove':
        db.session.delete(rv)
    else:
        rv.flagged=False
    db.session.commit()
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/resources/create', methods=['GET','POST'])
@login_required
def create_resource():
    if current_user.role not in ['admin','staff']:
        abort(403)
    form = ResourceForm()
    if form.validate_on_submit():
        try:
            capacity = int(form.capacity.data)
        except:
            flash('Invalid capacity.','danger')
            return render_template('admin_create_resource.html', form=form)
        
        # Process uploaded image file
        img_urls_list = []
        
        # Handle uploaded file
        if form.image_file.data:
            try:
                uploaded_path = process_and_crop_image(form.image_file.data)
                img_urls_list.append(uploaded_path)
            except Exception as e:
                flash(f'Error processing uploaded image: {str(e)}','danger')
                return render_template('admin_create_resource.html', form=form)
        
        # Handle URL inputs (optional)
        if form.images.data and form.images.data.strip():
            url_list = [url.strip() for url in form.images.data.split(',')]
            processed_urls = []
            for url in url_list:
                if url:
                    # Convert Google Drive links if needed
                    if 'drive.google.com' in url and '/file/d/' in url:
                        file_id = url.split('/file/d/')[1].split('/')[0]
                        url = f"https://drive.google.com/uc?export=view&id={file_id}"
                    processed_urls.append(url)
            img_urls_list.extend(processed_urls)
        
        # Enforce single image per resource (keep only the first)
        if img_urls_list:
            img_urls_list = img_urls_list[:1]
        img_urls = ','.join(img_urls_list) if img_urls_list else None
        
        # New resources are published by default; admins can hide later
        initial_status = 'published'
        resource = Resource(
            owner_id=current_user.user_id,
            title=form.title.data,
            description=form.description.data or None,
            category=form.category.data,
            location=form.location.data,
            capacity=capacity,
            images=img_urls,
            availability_rules=form.availability_rules.data or None,
            restriction=form.restriction.data,
            status=initial_status
        )
        db.session.add(resource)
        db.session.commit()
        if initial_status == 'published':
            flash('Resource created and published.','success')
        else:
            flash('Resource saved as draft.','info')
        return redirect(url_for('admin.dashboard'))
    return render_template('admin_create_resource.html', form=form)

@admin_bp.route('/resources/<int:resource_id>/edit', methods=['GET','POST'])
@login_required
def edit_resource(resource_id):
    if current_user.role not in ['admin','staff']:
        abort(403)
    resource = Resource.query.get_or_404(resource_id)
    form = ResourceForm(obj=resource)
    # Pre-populate images field with existing images
    if resource.images:
        form.images.data = resource.images
    
    if form.validate_on_submit():
        try:
            capacity = int(form.capacity.data)
        except:
            flash('Invalid capacity.','danger')
            return render_template('admin_edit_resource.html', form=form, resource=resource)
        
        # Process uploaded image file (only if new file uploaded)
        img_urls_list = []
        
        # If new file uploaded, process it
        if form.image_file.data:
            try:
                uploaded_path = process_and_crop_image(form.image_file.data)
                img_urls_list.append(uploaded_path)
            except Exception as e:
                flash(f'Error processing uploaded image: {str(e)}','danger')
                return render_template('admin_edit_resource.html', form=form, resource=resource)
        
        # Handle URL inputs (optional)
        if form.images.data and form.images.data.strip():
            url_list = [url.strip() for url in form.images.data.split(',') if url.strip()]
            processed_urls = []
            for url in url_list:
                # Convert Google Drive links if needed
                if 'drive.google.com' in url and '/file/d/' in url:
                    file_id = url.split('/file/d/')[1].split('/')[0]
                    url = f"https://drive.google.com/uc?export=view&id={file_id}"
                processed_urls.append(url)
            # If new file was uploaded, add it first, then URLs
            if form.image_file.data:
                img_urls_list.extend(processed_urls)
            else:
                # No new file, use the URLs provided
                img_urls_list = processed_urls
        elif not form.image_file.data and resource.images:
            # No new file and no URLs provided, keep existing images (split existing comma-separated string)
            existing_imgs = resource.images.split(',') if resource.images else []
            img_urls_list = [img.strip() for img in existing_imgs if img.strip()]
        
        # Enforce single image per resource (keep only the first)
        if img_urls_list:
            img_urls_list = img_urls_list[:1]
        img_urls = ','.join(img_urls_list) if img_urls_list else None
        
        # Update resource
        resource.title = form.title.data
        resource.description = form.description.data or None
        resource.category = form.category.data
        resource.location = form.location.data
        resource.capacity = capacity
        resource.images = img_urls
        resource.availability_rules = form.availability_rules.data or None
        resource.restriction = form.restriction.data
        
        db.session.commit()
        flash('Resource updated successfully!','success')
        return redirect(url_for('resources.detail', resource_id=resource_id))
    
    return render_template('admin_edit_resource.html', form=form, resource=resource)

@admin_bp.route('/resources/<int:resource_id>/<action>')
@login_required
def resource_moderation(resource_id, action):
    if current_user.role not in ['admin','staff']:
        abort(403)
    r = Resource.query.get_or_404(resource_id)
    if action in ['publish','approve','unhide']:
        r.status = 'published'
        flash(f'Resource "{r.title}" published.','success')
    elif action in ['archive','reject','hide']:
        if action == 'hide':
            r.status = 'draft'
            flash(f'Resource "{r.title}" hidden (moved to draft).','info')
        else:
            r.status = 'archived'
            flash(f'Resource "{r.title}" archived.','warning')
    else:
        abort(400)
    db.session.commit()
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/resources/<int:resource_id>/delete', methods=['POST'])
@login_required
def delete_resource(resource_id):
    if current_user.role not in ['admin','staff']:
        abort(403)
    resource = Resource.query.get_or_404(resource_id)
    resource_title = resource.title
    
    # Delete associated bookings and reviews
    Booking.query.filter_by(resource_id=resource_id).delete()
    Review.query.filter_by(resource_id=resource_id).delete()
    
    # Delete the resource
    db.session.delete(resource)
    db.session.commit()
    
    flash(f'Resource "{resource_title}" deleted successfully.','success')
    return redirect(url_for('resources.browse'))

@users_bp.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    form = ProfileForm(obj=current_user)
    pwd_form = PasswordForm()
    notif_form = NotificationsForm()
    notif_form.email_updates.data = 'y' if current_user.notif_email_updates else 'n'
    notif_form.booking_alerts.data = 'y' if current_user.notif_booking_alerts else 'n'
    if form.validate_on_submit() and request.form.get('csrf_token')==form.csrf_token.current_token:
        current_user.name = form.name.data
        db.session.commit()
        flash('Profile updated.','success')
        return redirect(url_for('users.profile'))
    return render_template('profile.html', form=form, pwd_form=pwd_form, notif_form=notif_form)

@users_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    form = PasswordForm()
    if form.validate_on_submit():
        if not bcrypt.verify(form.current.data, current_user.password_hash):
            flash('Current password incorrect.','danger')
        elif form.new.data != form.confirm.data:
            flash('New passwords do not match.','danger')
        else:
            current_user.password_hash = bcrypt.hash(form.new.data)
            db.session.commit()
            flash('Password changed.','success')
    return redirect(url_for('users.profile'))

@users_bp.route('/notifications', methods=['POST'])
@login_required
def notifications():
    form = NotificationsForm()
    if form.validate_on_submit():
        current_user.notif_email_updates = form.email_updates.data=='y'
        current_user.notif_booking_alerts = form.booking_alerts.data=='y'
        db.session.commit()
        flash('Notification preferences saved.','success')
    return redirect(url_for('users.profile'))

@messages_bp.route('/')
@login_required
def inbox():
    thread_rows = get_inbox_threads(db, current_user.user_id)
    threads=[type('T',(),{'other_id':row[0],'count':row[1],'other_name':(User.query.get(row[0]).name if row[0] else 'Unknown')}) for row in thread_rows]
    return render_template('messages_inbox.html', threads=threads)

@messages_bp.route('/new', methods=['GET'])
@login_required
def new_with_user():
    if current_user.role!='admin': abort(403)
    email = request.args.get('email','').lower()
    u = User.query.filter_by(email=email).first()
    if not u:
        flash('User not found.','danger'); return redirect(url_for('messages.inbox'))
    return redirect(url_for('messages.thread', user_id=u.user_id))

@messages_bp.route('/with/<int:user_id>', methods=['GET','POST'])
@login_required
def thread(user_id):
    other = User.query.get_or_404(user_id)
    if current_user.role!='admin' and other.role!='admin' and other.user_id!=current_user.user_id:
        owns_resource = Resource.query.filter_by(owner_id=other.user_id).first() is not None
        if not owns_resource:
            abort(403)
    class MessageForm(FlaskForm):
        content = StringField('Message', validators=[InputRequired(), Length(min=1, max=500)])
    form = MessageForm()
    if request.method=='POST' and form.validate_on_submit():
        m = Message(sender_id=current_user.user_id, receiver_id=other.user_id, content=bleach.clean(form.content.data, strip=True))
        db.session.add(m); db.session.commit()
        return redirect(url_for('messages.thread', user_id=user_id))
    msgs = Message.query.filter(
        db.or_(db.and_(Message.sender_id==current_user.user_id, Message.receiver_id==user_id),
               db.and_(Message.sender_id==user_id, Message.receiver_id==current_user.user_id))
    ).order_by(Message.timestamp.asc()).all()
    return render_template('messages_thread.html', other=other, msgs=msgs, form=form)

@auth_bp.route('/login', methods=['GET','POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        u = User.query.filter_by(email=form.email.data.lower()).first()
        if u and bcrypt.verify(form.password.data, u.password_hash):
            if not u.is_approved and u.role!='admin':
                flash('Your account is awaiting admin approval.','warning')
                return redirect(url_for('auth.login'))
            login_user(u)
            return redirect(url_for('main.home'))
        flash('Invalid credentials.','danger')
    return render_template('login.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.home'))

@auth_bp.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data.lower()).first():
            flash('Email already registered.','danger')
        else:
            req_admin = (request.form.get('request_admin')=='yes')
            u = User(name=form.name.data, email=form.email.data.lower(), role=form.role.data, is_approved=False,
                     password_hash=bcrypt.hash(form.password.data), request_admin=req_admin)
            db.session.add(u); db.session.commit()
            flash('Registered. Await admin approval.','success')
            return redirect(url_for('auth.login'))
    return render_template('register.html', form=form)

@reports_bp.route('/summary')
@login_required
def weekly_summary():
    if current_user.role not in ['admin', 'staff']:
        abort(403)
    today = datetime.date.today()
    start_day = today - datetime.timedelta(days=6)
    start_dt = datetime.datetime.combine(start_day, datetime.time.min)
    end_dt = datetime.datetime.combine(today, datetime.time.max)

    window_bookings = Booking.query.filter(
        Booking.start_datetime >= start_dt,
        Booking.start_datetime <= end_dt,
        Booking.status.in_(['approved', 'completed'])
    ).all()

    total_bookings = len(window_bookings)
    by_resource = {}
    categories = set()
    for b in window_bookings:
        r = b.resource
        if not r:
            continue
        key = r.resource_id
        categories.add(r.category or '')
        if key not in by_resource:
            by_resource[key] = {'id': r.resource_id, 'title': r.title, 'category': r.category, 'count': 0}
        by_resource[key]['count'] += 1

    distinct_resources = len(by_resource)
    active_categories = len([c for c in categories if c])
    top_resources = sorted(by_resource.values(), key=lambda x: x['count'], reverse=True)[:5]

    # Quiet resources: published with no bookings in the window
    all_published = Resource.query.filter_by(status='published').all()
    busy_ids = set(by_resource.keys())
    quiet_resources = [r for r in all_published if r.resource_id not in busy_ids]

    stats = dict(
        total_bookings=total_bookings,
        distinct_resources=distinct_resources,
        active_categories=active_categories,
    )

    # Optional: delegate narrative generation to Google Gemini if configured.
    # Gemini is called with a prompt that embeds structured project data and high-level context
    # from docs/context/ while forbidding fabricated facts.
    narrative = None
    gemini_key = os.environ.get('AIzaSyC1k0gcYEN-vGVhRiRpTErqXXwLQeFf3-I')
    if gemini_key:
        try:
            summary_data = {
                "window": {
                    "start_day": start_day.isoformat(),
                    "end_day": today.isoformat(),
                },
                "stats": stats,
                "top_resources": top_resources,
                "quiet_resources_count": len(quiet_resources),
            }
            # Pull a small amount of context from docs/context/* if available
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            context_paths = [
                os.path.join(base_dir, "docs", "context", "DT", "README.md"),
                os.path.join(base_dir, "docs", "context", "APA", "README.md"),
                os.path.join(base_dir, "docs", "context", "PM", "README.md"),
            ]
            context_snippets = []
            for p in context_paths:
                try:
                    with open(p, encoding="utf-8") as f:
                        text = f.read().strip()
                        if text:
                            context_snippets.append(text[:500])
                except FileNotFoundError:
                    continue
            context_text = "\n\n".join(context_snippets) if context_snippets else ""

            prompt_text = (
                "You are an assistant generating a concise weekly summary of campus resource usage "
                "for an internal admin dashboard.\n\n"
                "First, read the high-level design context below. It may contain personas, goals, or "
                "acceptance tests from the project's docs/context folder. Use it only to adjust tone and "
                "emphasis (for example, highlighting study spaces if students value quiet group work), "
                "but do not invent new resources or numbers from it.\n\n"
                "CONTEXT FROM DOCS/CONTEXT (if any):\n"
                f"{context_text}\n\n"
                "Next, use ONLY the structured JSON data to state concrete facts such as counts, "
                "resource names, and time windows. Do not fabricate resources, dates, or metrics that "
                "are not present in the JSON.\n\n"
                "JSON data:\n"
                f"{json.dumps(summary_data, ensure_ascii=False)}"
            )
            url = (
                "https://generativelanguage.googleapis.com/v1beta/models/"
                "gemini-1.5-flash:generateContent"
                f"?key={gemini_key}"
            )
            payload = {"contents": [{"parts": [{"text": prompt_text}]}]}
            resp = requests.post(url, json=payload, timeout=5)
            resp.raise_for_status()
            data = resp.json()
            # Extract first candidate text if present
            candidates = data.get("candidates") or []
            if candidates:
                parts = candidates[0].get("content", {}).get("parts") or []
                if parts and "text" in parts[0]:
                    text = parts[0]["text"].strip()
                    if text:
                        narrative = text
        except Exception:
            narrative = None

    if narrative is None:
        if total_bookings == 0:
            narrative = (
                "In the last 7 days there were no approved or completed bookings. "
                "This is a good opportunity to promote key resources or simplify the booking process."
            )
        else:
            # Deterministic fallback summary (no external AI).
            if top_resources:
                leader = top_resources[0]
                leader_line = f"{leader['title']} stands out with {leader['count']} booking(s)."
            else:
                leader_line = ""

            cat_line = ""
            if active_categories > 0:
                cat_line = f" Activity spans {active_categories} categor{'y' if active_categories == 1 else 'ies'}."

            quiet_line = ""
            if quiet_resources:
                quiet_line = f" {len(quiet_resources)} published resource(s) had no bookings and may benefit from promotion."

            narrative = (
                f"Between {start_day.strftime('%b %d')} and {today.strftime('%b %d')}, "
                f"the system recorded {total_bookings} approved or completed booking(s) "
                f"across {distinct_resources} resource(s). "
                f"{leader_line}{cat_line}{quiet_line}"
            ).strip()

    return render_template(
        'reports_summary.html',
        narrative=narrative,
        stats=stats,
        top_resources=top_resources,
        quiet_resources=quiet_resources,
    )


@reports_bp.route('/api-docs')
def api_docs():
    return jsonify({
        "auth": {"POST /auth/login": {"email": "str", "password": "str"}, "GET /auth/logout": {}},
        "resources": ["GET /api/resources", "GET /api/resources/<id>", "GET /api/resources/<id>/reviews"],
        "bookings": ["POST /api/bookings", "GET /api/bookings/my"],
        "messages": ["GET /api/messages/with/<user_id>", "POST /api/messages/with/<user_id>"]
    })

@api_bp.route('/resources')
@login_required
def api_resources():
    rows = Resource.query.filter_by(status='published').all()
    return jsonify([{"id":r.resource_id,"title":r.title,"category":r.category,"location":r.location,"capacity":r.capacity} for r in rows])

@api_bp.route('/resources/<int:rid>')
@login_required
def api_resource_detail(rid):
    r = Resource.query.get_or_404(rid)
    return jsonify({"id":r.resource_id,"title":r.title,"desc":r.description,"images":(r.images or '').split(','),"restriction":r.restriction})

@api_bp.route('/resources/<int:rid>/reviews')
@login_required
def api_reviews(rid):
    rows = Review.query.filter_by(resource_id=rid, flagged=False).all()
    return jsonify([{"reviewer":rv.reviewer.name,"rating":rv.rating,"comment":rv.comment} for rv in rows])

@api_bp.route('/bookings', methods=['POST'])
@login_required
def api_booking():
    data = request.get_json(force=True)
    rid = int(data.get('resource_id')); date=data.get('date'); slot=data.get('slot')
    # Validate presence and coherence of date/slot
    try:
        start,end = parse_slot(date, slot)
    except Exception:
        return jsonify({"ok": False, "error": "Invalid date or slot"}), 400
    now = datetime.datetime.utcnow()
    if end <= start:
        return jsonify({"ok": False, "error": "End must be after start"}), 400
    if start.date() < now.date():
        return jsonify({"ok": False, "error": "Cannot book past dates"}), 400
    if start.date() > (now.date() + datetime.timedelta(days=365)):
        return jsonify({"ok": False, "error": "Too far in advance"}), 400
    b = Booking(resource_id=rid, requester_id=current_user.user_id, start_datetime=start, end_datetime=end, status='pending')
    db.session.add(b); db.session.commit()
    return jsonify({"ok":True, "booking_id":b.booking_id})

@api_bp.route('/bookings/my')
@login_required
def api_my_bookings():
    rows = Booking.query.filter_by(requester_id=current_user.user_id).all()
    return jsonify([{"id":b.booking_id,"resource":b.resource.title,"status":b.status} for b in rows])

@api_bp.route('/trends/hourly')
@login_required
def api_trends_hourly():
    if current_user.role not in ['admin','staff']:
        abort(403)
    day = request.args.get('date')
    try:
        target = datetime.datetime.strptime(day, '%Y-%m-%d').date() if day else datetime.date.today()
    except Exception:
        target = datetime.date.today()
    hours = [f"{h:02d}" for h in range(24)]
    mapping = get_hourly_bookings(db, target)
    values = [mapping.get(h, 0) for h in hours]
    return jsonify({"labels": hours, "values": values, "date": target.strftime('%Y-%m-%d')})

app.register_blueprint(main_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(resources_bp)
app.register_blueprint(bookings_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(users_bp)
app.register_blueprint(messages_bp)
app.register_blueprint(reports_bp)
app.register_blueprint(api_bp)

import click

@app.cli.command('db-init')
@click.option('--reset', is_flag=True, help='Drop and recreate tables')
def db_init(reset):
    if reset:
        db.drop_all()
    db.create_all()
    if not User.query.filter_by(email='admin@example.com').first():
        admin = User(name='Admin', email='admin@example.com', role='admin', is_approved=True, password_hash=bcrypt.hash('password'))
        staff = User(name='Staff', email='staff@example.com', role='staff', is_approved=True, password_hash=bcrypt.hash('password'), department='AV')
        student = User(name='Student', email='student@example.com', role='student', is_approved=True, password_hash=bcrypt.hash('password'), department='Physics')
        db.session.add_all([admin, staff, student]); db.session.commit()
    def img(n): return f"/static/img/{n}.png"
    if Resource.query.count()==0:
        res = [
            Resource(owner_id=1, title='Classroom A', description='Standard classroom with projector.', category='Classroom', location='Main Building', capacity=30, images=img(1), status='published', restriction='open'),
            Resource(owner_id=1, title='Meeting Room 1', description='Cozy meeting space.', category='Conference Room', location='North Wing', capacity=12, images=img(2), status='published', restriction='restricted'),
            Resource(owner_id=1, title='Physics Lab', description='Lab equipment provided.', category='Lab', location='Science Center', capacity=20, images=img(3), status='published', restriction='restricted'),
            Resource(owner_id=1, title='Projector', description='HD projector with HDMI.', category='Equipment', location='Science Center', capacity=1, images=img(4), status='published', restriction='open'),
        ]
        db.session.add_all(res); db.session.commit()
    click.echo("DB initialized.")

@app.cli.command('make-admin')
@click.argument('email')
def make_admin(email):
    u = User.query.filter_by(email=email.lower()).first()
    if not u: click.echo("User not found."); return
    u.is_approved=True; u.role='admin'; u.request_admin=False; db.session.commit(); click.echo("Promoted.")

if __name__ == '__main__':
    app.run()
