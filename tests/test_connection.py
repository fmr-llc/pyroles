import unittest
from pyroles.pyroles import PyRoles
from nose.plugins.attrib import attr
from pyroles import conf_pyroles


class ConnectionCase(unittest.TestCase):
        
    @attr(scope=["local"])
    @attr("pyroles")
    @attr("connection")
    def test_connect_on_init(self):
        pr = PyRoles(conf_pyroles.dbUrl)
        assert pr.connected, "Expected to have a connection to the db, but did not"
        pr.close()
        assert pr.connected == False, "Expected not to have a connection to the db after calling close, but did"

    @attr(scope=["local"])
    @attr("pyroles")
    @attr("connection")
    def test_connect_to_existing_session(self):
        pr = PyRoles()
        pr.connect(conf_pyroles.dbUrl)
        assert pr.connected, "Expected to have a connection to the db, but did not"
        session = pr._session # pylint: disable=W0212
        pr2 = PyRoles()
        pr2.connect_to_existing_session(session)
        assert pr2.connected, "Expected to have a connection to the db after connecting to an existing session, but did not"
        pr.close()
        assert pr.connected == False, "Expected not to have a connection to the db after calling close, but did"
        pr2.close()
        assert pr2.connected == False, "Expected not to have a connection to the db after calling close on the second PyRoles object, but did"

    @attr(scope=["local"])
    @attr("pyroles")
    @attr("connection")
    def test_connect_to_existing_session_already_connected(self):
        pr = PyRoles()
        pr.connect(conf_pyroles.dbUrl)
        assert pr.connected, "Expected to have a connection to the db, but did not"
        session = pr._session # pylint: disable=W0212
        pr2 = PyRoles()
        pr2.connect_to_existing_session(session)
        assert pr2.connected, "Expected to have a connection to the db after connecting to an existing session, but did not"
        try: 
            pr2.connect_to_existing_session(session)
            self.fail("Expected to get an exception when calling connect_to_existing_session if we were already connected, but did not!")
        except Exception as e:
            assert e.message == "Already Connected", "Expected to get an exception when calling connect_to_existing_session if we were already connected, but did not!"
                
        pr.close()
        assert pr.connected == False, "Expected not to have a connection to the db after calling close, but did"
        pr2.close()
        assert pr2.connected == False, "Expected not to have a connection to the db after calling close on the second PyRoles object, but did"

    @attr(scope=["local"])
    @attr("pyroles")
    @attr("connection")
    def test_close(self):
        pr = PyRoles(conf_pyroles.dbUrl)
        pr.close()
        assert pr.connected == False, "Expected not to have a connection to the db after calling close, but did"

    @attr(scope=["local"])
    @attr("pyroles")
    @attr("connection")
    def test_close_not_connected(self):
        pr = PyRoles(conf_pyroles.dbUrl)
        pr.close()
        assert pr.connected == False, "Expected not to have a connection to the db after calling close, but did"
        pr.close()
        assert pr.connected == False, "Expected not to have a connection to the db after calling close, but did"
