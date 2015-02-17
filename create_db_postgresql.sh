su - postgres -c "createuser -s pyroles"
su - postgres -c "createdb pyroles -O pyroles"
su - postgres -c "psql -c \"ALTER USER pyroles WITH PASSWORD 'pyroles';\""
su - postgres -d pyroles -c "psql -c \"create SCHEMA pyroles AUTHORIZATION pyroles;\""
