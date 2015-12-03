# jenkins_uom_auth
Backend authentication and group discovery scripts for jenkins.

These scripts support authentication of users against an LDAP service (via TLS) and retrieval and reporting of user groups from a MySQL database server. 

In order to use these scripts, the jenkins server must be using the [Security Realm by custom script](https://wiki.jenkins-ci.org/display/JENKINS/Script+Security+Realm) authentication plugin.
