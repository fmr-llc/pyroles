mysql -u root --password=password -e "create user 'pyroles'"
mysql -u root --password=password -e "create user 'pyroles'@'localhost'"
mysql -u root --password=password -e "set password for 'pyroles' = password('pyroles')"
mysql -u root --password=password -e "set password for 'pyroles'@'localhost' = password('pyroles')"
mysql -u root --password=password -e "grant create on *.* to 'pyroles'"
mysql -u root --password=password -e "grant create on *.* to 'pyroles'@'localhost'"
mysql -u root --password=password -e "create database pyroles"
mysql -u root --password=password -e "grant all on *.* to 'pyroles'@'localhost'"
