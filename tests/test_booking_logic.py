import datetime as dt


def test_conflict_detection_and_availability(client):
    # Arrange: create user, resource, and an existing booking from 10:00-11:00
    from src import app as appmod
    with appmod.app.app_context():
        u = appmod.User(name="T", email="t@example.com", role="student", is_approved=True, password_hash=appmod.bcrypt.hash("pw"))
        r = appmod.Resource(owner_id=None, title="Room A", description="", category="Classroom", location="B1", capacity=10, status='published', restriction='open')
        appmod.db.session.add_all([u, r]); appmod.db.session.commit()
        date = dt.date.today() + dt.timedelta(days=1)
        start = dt.datetime.combine(date, dt.time(hour=10))
        end = dt.datetime.combine(date, dt.time(hour=11))
        b = appmod.Booking(resource_id=r.resource_id, requester_id=u.user_id, start_datetime=start, end_datetime=end, status='approved')
        appmod.db.session.add(b); appmod.db.session.commit()

        # Act: compute busy and available slots
        busy = appmod.busy_slots(r.resource_id, date)
        avail = appmod.available_slots(r.resource_id, date)

        # Assert
        assert '10:00-11:00' in busy
        assert '10:00-11:00' not in avail
        assert all(s in appmod.SLOTS for s in avail)


def test_status_transition_open_vs_restricted(client):
    # Arrange users and two resources
    from src import app as appmod
    app = appmod.app
    with app.app_context():
        u = appmod.User(name="Sally", email="sally@example.com", role="student", is_approved=True, password_hash=appmod.bcrypt.hash("pw"))
        open_r = appmod.Resource(owner_id=None, title="Open Room", description="", category="Classroom", location="B1", capacity=10, status='published', restriction='open')
        rest_r = appmod.Resource(owner_id=None, title="Restricted Room", description="", category="Classroom", location="B2", capacity=10, status='published', restriction='restricted')
        appmod.db.session.add_all([u, open_r, rest_r]); appmod.db.session.commit()

    # Login
    resp = client.post('/auth/login', data={"email":"sally@example.com","password":"pw"}, follow_redirects=True)
    assert resp.status_code == 200

    # Book open resource -> auto-approved
    date_str = (dt.date.today() + dt.timedelta(days=2)).strftime('%Y-%m-%d')
    resp = client.post(f"/bookings/request/{open_r.resource_id}", data={"date":date_str, "slot":"09:00-10:00"}, follow_redirects=True)
    assert resp.status_code == 200
    with app.app_context():
        b1 = appmod.Booking.query.filter_by(resource_id=open_r.resource_id, requester_id=u.user_id).first()
        assert b1 is not None and b1.status == 'approved'

    # Book restricted resource -> pending
    resp = client.post(f"/bookings/request/{rest_r.resource_id}", data={"date":date_str, "slot":"11:00-12:00"}, follow_redirects=True)
    assert resp.status_code == 200
    with app.app_context():
        b2 = appmod.Booking.query.filter_by(resource_id=rest_r.resource_id, requester_id=u.user_id).first()
        assert b2 is not None and b2.status == 'pending'

