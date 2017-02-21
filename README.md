# artemis-oauth2-login-module

This is an example of creating your own Security Plugin for ActiveMQ Artemis.

As described in ActiveMQ Artemis documentation (https://activemq.apache.org/artemis/docs/1.5.2/security.html), there are a number of available plugins that come with Artemis.  In addition to those plugins, you can also create your own plugin and apply any custom logic.

In this project, an OAuth2 Login Module is created to demonstrate this capability.

To use this module, build the project and then copy to ${ARTEMIS_HOME}/lib.  This invoke the module via the ${BROKER_HOME}/etc/login.config file.
