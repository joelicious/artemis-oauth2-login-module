# artemis-oauth2-login-module

This is an example of creating your own Security Plugin for ActiveMQ Artemis.

As described in ActiveMQ Artemis documentation (https://activemq.apache.org/artemis/docs/1.5.2/security.html), there are a number of available plugins that come with Artemis.  In addition to those plugins, you can also create your own plugin and apply any custom logic.

This project is described in the following blog post:
https://medium.com/@joelicious/extending-artemis-security-with-oauth2-7fd9b3dffe3#.fw0y2tt0y

To use this module, build the project and then copy to ${ARTEMIS_HOME}/lib. It then can be invoked by updating the  ${BROKER_HOME}/etc/login.config file.
