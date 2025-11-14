def test_dal_crud_independent_of_routes(db_session):
    # Create
    from src import app as appmod
    u = appmod.User(name="Alice", email="alice@example.com", role="student", is_approved=True, password_hash=appmod.bcrypt.hash("pw"))
    db_session.session.add(u); db_session.session.commit()
    assert u.user_id is not None

    # Read
    fetched = appmod.User.query.filter_by(email="alice@example.com").first()
    assert fetched and fetched.name == "Alice"

    # Update
    fetched.department = "Physics"
    db_session.session.commit()
    again = appmod.User.query.get(fetched.user_id)
    assert again.department == "Physics"

    # Delete
    db_session.session.delete(again)
    db_session.session.commit()
    gone = appmod.User.query.filter_by(email="alice@example.com").first()
    assert gone is None

