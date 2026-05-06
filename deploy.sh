

echo "Installing dependencies..."
pip install django cryptography matplotlib numpy

echo "Running database migrations..."
python manage.py migrate

echo "Starting Django development server..."
python manage.py runserver 0.0.0.0:5000