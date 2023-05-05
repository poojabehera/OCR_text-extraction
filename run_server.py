import os
from app.main import create_app,rest_workers
from app import blueprint
config_name = os.getenv('SD_APP_ENV') or 'dev'
app = create_app(config_name)
app.register_blueprint(blueprint)
app.app_context().push()
rest_workers(app)

if __name__ == '__main__':
    app.run()