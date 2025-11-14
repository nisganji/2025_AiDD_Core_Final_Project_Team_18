import datetime as dt


def test_e2e_booking_flow(client):
    # Create an approved user and a published resource
    from src import app as appmod
    app = appmod.app
    with app.app_context():
        u = appmod.User(name="Eva", email="eva@example.com", role="student", is_approved=True, password_hash=appmod.bcrypt.hash("pw"))
        r = appmod.Resource(owner_id=None, title="Lab A", description="", category="Lab", location="C1", capacity=5, status='published', restriction='open')
        appmod.db.session.add_all([u, r]); appmod.db.session.commit()

    # Login
    rv = client.post('/auth/login', data={'email':'eva@example.com','password':'pw'}, follow_redirects=True)
    assert rv.status_code == 200

    # Visit resource detail
    rv = client.get(f"/resources/{r.resource_id}")
    assert rv.status_code == 200

    # Book a free slot
    date_str = (dt.date.today() + dt.timedelta(days=3)).strftime('%Y-%m-%d')
    rv = client.post(f"/bookings/request/{r.resource_id}", data={'date': date_str, 'slot': '08:00-09:00'}, follow_redirects=True)
    assert rv.status_code == 200

    # My bookings should show the booking
    rv = client.get('/bookings/my')
    assert rv.status_code == 200
    assert b'Lab A' in rv.data

