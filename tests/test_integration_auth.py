def test_register_login_access_protected(client):
    # Register new user
    rv = client.post('/auth/register', data={
        'name':'Bob', 'email':'bob@example.com', 'password':'pw', 'role':'student'
    }, follow_redirects=True)
    assert rv.status_code == 200

    # Approve user directly in DB (simulating admin approval)
    from src import app as appmod
    with appmod.app.app_context():
        u = appmod.User.query.filter_by(email='bob@example.com').first()
        assert u is not None
        u.is_approved = True
        appmod.db.session.commit()

    # Login
    rv = client.post('/auth/login', data={'email':'bob@example.com','password':'pw'}, follow_redirects=True)
    assert rv.status_code == 200
    assert b'Sign out' in rv.data  # navbar shows sign out when logged in

    # Access protected route
    rv = client.get('/bookings/my')
    assert rv.status_code == 200

