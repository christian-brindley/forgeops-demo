#!/bin/bash

#
# Copyright 2019-2020 ForgeRock AS. All Rights Reserved
#

. $FORGEROCK_HOME/debug.sh
. $FORGEROCK_HOME/profiling.sh

CATALINA_OPTS="$CATALINA_OPTS $AM_CONTAINER_JVM_ARGS $CATALINA_USER_OPTS $JFR_OPTS"

# TODO check we have secrets directory mounted
# TODO remove -encrypted attributes

copy_secrets() {
    mkdir -p $AM_HOME/var/audit
    DEFAULT_SECRETS_DIR=$AM_HOME/security/secrets/default
    ENCRYPTED_SECRETS_DIR=$AM_HOME/security/secrets/encrypted
    AMSTER_SECRETS_DIR=$AM_HOME/security/keys/amster
    KEYSTORE_DIR=$AM_HOME/security/keystores

    mkdir -p $DEFAULT_SECRETS_DIR
    mkdir -p $ENCRYPTED_SECRETS_DIR
    mkdir -p $KEYSTORE_DIR
    mkdir -p $AMSTER_SECRETS_DIR
    echo "Copying bootstrap files for legacy AMKeyProvider"

    rm -f $DEFAULT_SECRETS_DIR/.storepass $DEFAULT_SECRETS_DIR/.keypass
    cp $AM_SECRETS_PATH/.storepass $DEFAULT_SECRETS_DIR
    cp $AM_SECRETS_PATH/.keypass $DEFAULT_SECRETS_DIR
    cat $AM_HOME/security/secrets/default/.storepass | am-crypto encrypt des > $ENCRYPTED_SECRETS_DIR/storepass
    cat $AM_HOME/security/secrets/default/.keypass | am-crypto encrypt des > $ENCRYPTED_SECRETS_DIR/entrypass
    cp $AM_SECRETS_PATH/.storepass $KEYSTORE_DIR
    cp $AM_SECRETS_PATH/.keypass $KEYSTORE_DIR
    cp $AM_SECRETS_PATH/keystore.jceks $KEYSTORE_DIR

    cp $AMSTER_SECRETS_PATH/* $AMSTER_SECRETS_DIR
}

generateRandomSecret() {
    cat /dev/urandom | tr -dc 'A-Za-z0-9' | fold -w 32 | head -n 1
}

am-crypto() {
    java -jar /home/forgerock/crypto-tool.jar $@
}

export SECRETS_PATH=${SECRETS_PATH:-/var/run/secrets}
export AM_SECRETS_PATH=${AM_SECRETS_PATH:-$SECRETS_PATH/am}
export AMSTER_SECRETS_PATH=${AMSTER_SECRETS_PATH:-$SECRETS_PATH/amster}

export AM_SERVER_PROTOCOL=${AM_SERVER_PROTOCOL:-"https"}
export AM_SERVER_FQDN=${AM_SERVER_FQDN:-"default.iam.example.com"}
export AM_SERVER_PORT=${AM_SERVER_PORT:-80}

export AM_STORES_USER_TYPE=${AM_STORES_USER_TYPE:-"LDAPv3ForOpenDS"}

export AM_ENCRYPTION_KEY=${AM_ENCRYPTION_KEY:-$(generateRandomSecret)}

copy_secrets

AM_PASSWORDS_DSAMEUSER_CLEAR=$(generateRandomSecret)
export AM_PASSWORDS_DSAMEUSER_HASHED_ENCRYPTED=$(echo $AM_PASSWORDS_DSAMEUSER_CLEAR | am-crypto hash encrypt des)
export AM_PASSWORDS_DSAMEUSER_ENCRYPTED=$(echo $AM_PASSWORDS_DSAMEUSER_CLEAR | am-crypto encrypt des)

AM_PASSWORDS_ANONYMOUS_CLEAR=${AM_PASSWORDS_ANONYMOUS_CLEAR:-$(generateRandomSecret)}
AM_PASSWORDS_ANONYMOUS_HASHED=${AM_PASSWORDS_ANONYMOUS_HASHED:-$(echo $AM_PASSWORDS_ANONYMOUS_CLEAR | am-crypto hash)}
export AM_PASSWORDS_ANONYMOUS_HASHED_ENCRYPTED=$(echo $AM_PASSWORDS_ANONYMOUS_HASHED | am-crypto encrypt des)

AM_PASSWORDS_AMADMIN_HASHED=${AM_PASSWORDS_AMADMIN_HASHED:-$(echo $AM_PASSWORDS_AMADMIN_CLEAR | am-crypto hash)}
unset AM_PASSWORDS_AMADMIN_CLEAR
export AM_PASSWORDS_AMADMIN_HASHED_ENCRYPTED=$(echo $AM_PASSWORDS_AMADMIN_HASHED | am-crypto encrypt des)

export AM_KEYSTORE_DEFAULT_PASSWORD=$(cat $AM_HOME/security/secrets/default/.storepass)
export AM_KEYSTORE_DEFAULT_ENTRY_PASSWORD=$(cat $AM_HOME/security/secrets/default/.keypass)

export AM_STORES_USER_USERNAME="${AM_STORES_USER_USERNAME:-"uid=am-identity-bind-account,ou=admins,ou=identities"}"
export AM_STORES_USER_PASSWORD="${AM_STORES_USER_PASSWORD:-"password"}"
export AM_STORES_USER_SERVERS="${AM_STORES_USER_SERVERS:-"default.ds.example.com:1389"}"

export AM_STORES_CTS_USERNAME="${AM_STORES_CTS_USERNAME:-"uid=openam_cts,ou=admins,ou=famrecords,ou=openam-session,ou=tokens"}"
export AM_STORES_CTS_PASSWORD="${AM_STORES_CTS_PASSWORD:-"$AM_STORES_USER_PASSWORD"}"
export AM_STORES_CTS_SERVERS="${AM_STORES_CTS_SERVERS:-"$AM_STORES_USER_SERVERS"}"

export AM_STORES_APPLICATION_USERNAME="${AM_STORES_APPLICATION_USERNAME:-"uid=am-config,ou=admins,ou=am-config"}"
export AM_STORES_APPLICATION_PASSWORD="${AM_STORES_APPLICATION_PASSWORD:-"$AM_STORES_USER_PASSWORD"}"
export AM_STORES_APPLICATION_SERVERS="${AM_STORES_APPLICATION_SERVERS:-"$AM_STORES_USER_SERVERS"}"

export AM_STORES_POLICY_USERNAME="${AM_STORES_POLICY_USERNAME:-"uid=am-config,ou=admins,ou=am-config"}"
export AM_STORES_POLICY_PASSWORD="${AM_STORES_POLICY_PASSWORD:-"$AM_STORES_APPLICATION_PASSWORD"}"
export AM_STORES_POLICY_SERVERS="${AM_STORES_POLICY_SERVERS:-"$AM_STORES_APPLICATION_SERVERS"}"

export AM_STORES_UMA_USERNAME="${AM_STORES_UMA_USERNAME:-"uid=am-config,ou=admins,ou=am-config"}"
export AM_STORES_UMA_PASSWORD="${AM_STORES_UMA_PASSWORD:-"$AM_STORES_APPLICATION_PASSWORD"}"
export AM_STORES_UMA_SERVERS="${AM_STORES_UMA_SERVERS:-"$AM_STORES_APPLICATION_SERVERS"}"

export AM_AUTHENTICATION_MODULES_LDAP_USERNAME="${AM_AUTHENTICATION_MODULES_LDAP_USERNAME:-"$AM_STORES_USER_USERNAME"}"
export AM_AUTHENTICATION_MODULES_LDAP_PASSWORD="${AM_AUTHENTICATION_MODULES_LDAP_PASSWORD:-"$AM_STORES_USER_PASSWORD"}"
export AM_AUTHENTICATION_MODULES_LDAP_SERVERS="${AM_AUTHENTICATION_MODULES_LDAP_SERVERS:-"$AM_STORES_USER_SERVERS"}"


export AM_AUTHENTICATION_SHARED_SECRET=$(echo -n "${AM_AUTHENTICATION_SHARED_SECRET:-$(generateRandomSecret)}" | base64)
export AM_SESSION_STATELESS_SIGNING_KEY=$(echo -n "${AM_SESSION_STATELESS_SIGNING_KEY:-$(generateRandomSecret)}" | base64)
export AM_SESSION_STATELESS_ENCRYPTION_KEY=$(echo -n "${AM_SESSION_STATELESS_ENCRYPTION_KEY:-$(generateRandomSecret)}" | base64)

export AM_OIDC_CLIENT_SUBJECT_IDENTIFIER_HASH_SALT="${AM_OIDC_CLIENT_SUBJECT_IDENTIFIER_HASH_SALT:-$(generateRandomSecret)}"

export AM_SELFSERVICE_LEGACY_CONFIRMATION_EMAIL_LINK_SIGNING_KEY=$(echo -n "${AM_SELFSERVICE_LEGACY_CONFIRMATION_EMAIL_LINK_SIGNING_KEY:-$(generateRandomSecret)}" | base64)


export AM_PROMETHEUS_PASSWORD_ENCRYPTED=$( echo -n "${AM_PROMETHEUS_PASSWORD:-prometheus}" | am-crypto encrypt des )

if [ ! -z "$JPDA_DEBUG" ]; then
  # For debugging purposes
  echo "****** Environment *************: "
  env | sort
fi

wait_for_datastore() {
  hostname=$(echo $2 | cut -d ":" -f1)
  echo "Waiting for $1 to be available. Trying $hostname:8080/alive endpoint" #What if multiple ds's are set?
  while [[ "$(curl -s -o /dev/null -w ''%{http_code}'' $hostname:8080/alive)" != "200" ]];
  do
          sleep 5;
  done
  echo "$1 is responding"
}

wait_for_datastore "User Store" "${AM_STORES_USER_SERVERS}"
wait_for_datastore "CTS" "${AM_STORES_CTS_SERVERS}"
wait_for_datastore "Application Store" "${AM_STORES_APPLICATION_SERVERS}"
wait_for_datastore "Policy Store" "${AM_STORES_POLICY_SERVERS}"
wait_for_datastore "UMA Store" "${AM_STORES_UMA_SERVERS}"

echo "Environment:"
env | sort

echo "Starting tomcat with opts: ${CATALINA_OPTS}"
exec $CATALINA_HOME/bin/catalina.sh $JPDA_DEBUG run
