import datetime as dt


def test_browse_resists_injection_and_handles_special_input(client):
    # Create one published resource with known title
    from src import app as appmod
    with appmod.app.app_context():
        r = appmod.Resource(owner_id=None, title="SafeRoom", description="desc", category="Classroom", location="B1", capacity=10, status='published', restriction='open')
        appmod.db.session.add(r); appmod.db.session.commit()

    # Malicious-like query should not error and should not match SafeRoom
    inj = "' OR 1=1 --"
    rv = client.get(f"/resources/?q={inj}")
    assert rv.status_code == 200
    assert b"SafeRoom" not in rv.data

    # Legit query matches
    rv = client.get("/resources/?q=SafeRoom")
    assert rv.status_code == 200
    assert b"SafeRoom" in rv.data


def test_template_escapes_review_content(client):
    # Setup: approved user, published resource, completed booking in the past
    from src import app as appmod
    app = appmod.app
    with app.app_context():
        u = appmod.User(name="Rev", email="rev@example.com", role="student", is_approved=True, password_hash=appmod.bcrypt.hash("pw"))
        r = appmod.Resource(owner_id=None, title="Textbook", description="", category="Equipment", location="Lib", capacity=1, status='published', restriction='open')
        appmod.db.session.add_all([u, r]); appmod.db.session.commit()
        # Completed approved booking yesterday
        y = dt.date.today() - dt.timedelta(days=1)
        start = dt.datetime.combine(y, dt.time(hour=10))
        end = dt.datetime.combine(y, dt.time(hour=11))
        b = appmod.Booking(resource_id=r.resource_id, requester_id=u.user_id, start_datetime=start, end_datetime=end, status='approved')
        appmod.db.session.add(b); appmod.db.session.commit()

    # Login
    rv = client.post('/auth/login', data={'email':'rev@example.com','password':'pw'}, follow_redirects=True)
    assert rv.status_code == 200

    # Post a review containing script tag
    rv = client.post(f"/resources/{r.resource_id}/reviews", data={
        'rating':'5',
        'comment':'<script>alert(1)</script>'
    }, follow_redirects=True)
    assert rv.status_code == 200

    # Ensure script tag is not present in rendered HTML
    assert b'<script>' not in rv.data
    # The text content should be present (sanitized/escaped)
    assert b'alert(1)' in rv.data

