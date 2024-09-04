# authservice
# Overview

This project is a web application developed using Django and Django REST Framework (DRF) with SQLite as the database. It provides endpoints for user authentication, password management, organization management, and includes email notifications for various events.

# Features
User authentication with JWT tokens
Password reset and change functionality
Organization and role management
Email notifications for registration, password updates, and login alerts
Setup Instructions
1. Clone the Repository
First, clone the repository to your local machine:

git clone <repository-url>
cd <repository-directory>

2. Create and Activate a Virtual Environment
Create a virtual environment to manage your project dependencies:

python3 -m venv venv
Activate the virtual environment:

On Windows:

venv\Scripts\activate
On macOS/Linux:

source venv/bin/activate
3. Install Dependencies
Install the required Python packages:

pip install django
pip install djangorestframework
pip install djangorestframework-simplejwt

4. Apply Migrations
Apply the database migrations to set up the initial database schema:

python manage.py makemigrations
python manage.py migrate

5. Run the Development Server
Start the Django development server:

python manage.py runserver
Your application should now be running at http://127.0.0.1:8000/.
