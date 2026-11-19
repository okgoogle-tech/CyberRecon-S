import cyberrecon.storage as storage


def test_registration_page_loads(
    client,
):
    """
    Registration page must be publicly available.
    """

    response = client.get(
        "/register"
    )

    assert response.status_code == 200

    assert (
        b"Create"
        in response.data
    )


def test_user_can_register(
    client,
    register_user,
):
    """
    Valid registration should create a user.
    """

    response = register_user(
        client
    )

    assert response.status_code == 200

    assert (
        b"Account created successfully"
        in response.data
    )


    user = storage.get_user_by_email(
        "test@example.com"
    )

    assert user is not None

    assert (
        user["username"]
        == "testuser"
    )


def test_password_is_not_stored_plaintext(
    client,
    register_user,
):
    """
    Passwords must be stored as hashes.
    """

    register_user(
        client
    )


    user = storage.get_user_by_email(
        "test@example.com"
    )


    assert user is not None

    assert (
        user["password_hash"]
        != "Testpass123"
    )

    assert (
        "Testpass123"
        not in user[
            "password_hash"
        ]
    )


def test_duplicate_email_rejected(
    client,
    register_user,
):
    """
    Two accounts cannot use the same email.
    """

    register_user(
        client
    )


    response = register_user(
        client,
        username="anotheruser",
        email="test@example.com",
    )


    assert response.status_code == 200

    assert (
        b"already registered"
        in response.data
    )


def test_duplicate_username_rejected(
    client,
    register_user,
):
    """
    Usernames must also be unique.
    """

    register_user(
        client
    )


    response = register_user(
        client,
        username="testuser",
        email="another@example.com",
    )


    assert response.status_code == 200

    assert (
        b"already registered"
        in response.data
    )


def test_short_password_rejected(
    client,
):
    """
    Passwords shorter than eight characters
    must fail validation.
    """

    response = client.post(
        "/register",
        data={
            "username":
                "testuser",

            "email":
                "test@example.com",

            "password":
                "short",

            "confirm_password":
                "short",
        },
    )


    assert response.status_code == 200

    assert (
        b"at least 8 characters"
        in response.data
    )


def test_password_confirmation_required(
    client,
):
    """
    Registration must reject mismatching passwords.
    """

    response = client.post(
        "/register",
        data={
            "username":
                "testuser",

            "email":
                "test@example.com",

            "password":
                "Testpass123",

            "confirm_password":
                "Different123",
        },
    )


    assert response.status_code == 200

    assert (
        b"Passwords do not match"
        in response.data
    )


def test_login_page_loads(
    client,
):
    """
    Login page must be publicly available.
    """

    response = client.get(
        "/login"
    )

    assert response.status_code == 200


def test_valid_login(
    client,
    register_user,
    login_user,
):
    """
    Correct credentials should create a session.
    """

    register_user(
        client
    )


    response = login_user(
        client
    )


    assert response.status_code == 302

    assert response.headers[
        "Location"
    ].endswith(
        "/dashboard"
    )


    with client.session_transaction() as session:

        assert (
            session["user_id"]
            is not None
        )

        assert (
            session["username"]
            == "testuser"
        )


def test_invalid_password_rejected(
    client,
    register_user,
    login_user,
):
    """
    Incorrect passwords must not authenticate.
    """

    register_user(
        client
    )


    response = login_user(
        client,
        password="WrongPassword123",
    )


    assert response.status_code == 200

    assert (
        b"Invalid email address or password"
        in response.data
    )


    with client.session_transaction() as session:

        assert (
            "user_id"
            not in session
        )


def test_unknown_email_rejected(
    client,
    login_user,
):
    """
    Unknown email addresses must not authenticate.
    """

    response = login_user(
        client,
        email="unknown@example.com",
    )


    assert response.status_code == 200

    assert (
        b"Invalid email address or password"
        in response.data
    )


def test_logout_clears_session(
    client,
    register_user,
    login_user,
):
    """
    Logout must destroy the login session.
    """

    register_user(
        client
    )

    login_user(
        client
    )


    response = client.post(
        "/logout"
    )


    assert response.status_code == 302


    with client.session_transaction() as session:

        assert (
            "user_id"
            not in session
        )

        assert (
            "username"
            not in session
        )


def test_logged_in_user_cannot_open_register(
    authenticated_client,
):
    """
    Logged-in users should be redirected away
    from registration.
    """

    response = (
        authenticated_client.get(
            "/register"
        )
    )


    assert response.status_code == 302

    assert response.headers[
        "Location"
    ].endswith(
        "/dashboard"
    )


def test_logged_in_user_cannot_open_login(
    authenticated_client,
):
    """
    Already authenticated users should not
    receive another login form.
    """

    response = (
        authenticated_client.get(
            "/login"
        )
    )


    assert response.status_code == 302

    assert response.headers[
        "Location"
    ].endswith(
        "/dashboard"
    )


def test_is_safe_local_redirect_unit():
    """Unit tests for is_safe_local_redirect helper."""
    from cyberrecon.app import is_safe_local_redirect

    # Safe local targets
    assert is_safe_local_redirect("/dashboard") is True
    assert is_safe_local_redirect("/history") is True
    assert is_safe_local_redirect("/new?target=https://example.com") is True
    assert is_safe_local_redirect("/about#catalog") is True

    # Unsafe external URLs
    assert is_safe_local_redirect("https://evil.com") is False
    assert is_safe_local_redirect("http://evil.com") is False
    assert is_safe_local_redirect("ftp://evil.com") is False

    # Protocol-relative URLs
    assert is_safe_local_redirect("//evil.com") is False
    assert is_safe_local_redirect("//evil.com/path") is False
    assert is_safe_local_redirect("///evil.com") is False

    # JavaScript and data schemes
    assert is_safe_local_redirect("javascript:alert(1)") is False
    assert is_safe_local_redirect("javascript:void(0)") is False
    assert is_safe_local_redirect("data:text/html,<script>alert(1)</script>") is False

    # Backslash and carriage return bypasses
    assert is_safe_local_redirect("/\\evil.com") is False
    assert is_safe_local_redirect("\\evil.com") is False
    assert is_safe_local_redirect("/dashboard\r\nLocation: https://evil.com") is False
    assert is_safe_local_redirect("/dashboard\nevil") is False
    assert is_safe_local_redirect("evil.com") is False
    assert is_safe_local_redirect("") is False
    assert is_safe_local_redirect(None) is False


def test_login_open_redirect_attack_vectors_blocked(client, register_user):
    """
    Login endpoint must reject malicious next redirect parameters
    and safely fall back to /dashboard.
    """
    register_user(client)

    malicious_targets = [
        "https://evil.com",
        "http://evil.com/phish",
        "//evil.com",
        "//evil.com/path",
        "///evil.com",
        "javascript:alert(document.cookie)",
        "javascript:fetch('https://evil.com')",
        "data:text/html;base64,PHNjcmlwdD4=",
        "/\\evil.com",
        "\\evil.com",
        "evil.com/dashboard",
    ]

    for evil in malicious_targets:
        # Get pre-login CSRF token
        get_res = client.get(f"/login?next={evil}")
        csrf_token = None
        for line in get_res.data.decode("utf-8").splitlines():
            if 'name="csrf_token"' in line:
                csrf_token = line.split('value="')[1].split('"')[0]
                break

        response = client.post(
            "/login",
            data={
                "email": "test@example.com",
                "password": "Testpass123",
                "next": evil,
                "csrf_token": csrf_token or "token",
            },
            follow_redirects=False,
        )

        assert response.status_code == 302
        location = response.headers["Location"]
        assert "evil.com" not in location
        assert "javascript:" not in location
        assert location.endswith("/dashboard"), f"Failed for evil vector: {evil}, got {location}"
