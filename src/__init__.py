"""Package initializer.

Make `from src import app as appmod` return the app module (src.app) so tests
can access the Flask instance via `appmod.app`.
Also re-export common symbols for convenience.
"""

import importlib as _importlib

# Expose the module so tests get a module object, not the Flask instance
app = _importlib.import_module(".app", __name__)

# Optional re-exports used by some imports
db = app.db
User = app.User
Resource = app.Resource
Booking = app.Booking
Review = app.Review
Message = app.Message
Notification = app.Notification
bcrypt = app.bcrypt

