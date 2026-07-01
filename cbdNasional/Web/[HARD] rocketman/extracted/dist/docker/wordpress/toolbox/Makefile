WP_CLI=wp-cli --allow-root

install: configure

configure:  
	@echo "⚙️ Configuring Wordpress database..."
	dockerize -wait tcp://wp_service_1_db:3306 -timeout 120s 2> /dev/null #2>&1
	@rm -f wp-config.php

	@echo "Sleeping for 10 seconds to let dust settle in..."
	@sleep 10
	@echo "Continuing..."

	$(WP_CLI) core config \
		--dbhost=${WORDPRESS_DB_HOST} \
		--dbname=${WORDPRESS_DB_NAME} \
		--dbuser=${WORDPRESS_DB_USER} \
		--dbpass=${WORDPRESS_DB_PASSWORD} \
		--locale=${WORDPRESS_LOCALE}
	@grep -q "JETPACK_DEV_DEBUG" wp-config.php || sed -i "1a define( 'JETPACK_DEV_DEBUG', true );" wp-config.php

	$(WP_CLI) core install \
		--url="${CHALL_SERVER_URL}" \
		--title="$(WORDPRESS_WEBSITE_TITLE)" \
		--admin_user=${WORDPRESS_ADMIN_USER} \
		--admin_password=${WORDPRESS_ADMIN_PASSWORD} \
		--admin_email=${WORDPRESS_ADMIN_EMAIL}

	$(WP_CLI) option update home "${CHALL_SERVER_URL}"
	$(WP_CLI) option update siteurl "${CHALL_SERVER_URL}"
	$(WP_CLI) rewrite structure $(WORDPRESS_WEBSITE_POST_URL_STRUCTURE)
	@mkdir -p /var/www/html/wp-content/plugins/plugin-custom
	@cp -f /plugins/plugin-custom/plugin-custom.php /var/www/html/wp-content/plugins/plugin-custom/plugin-custom.php
	$(WP_CLI) plugin delete akismet
	$(WP_CLI) plugin delete hello-dolly
	$(WP_CLI) plugin activate plugin-custom
	$(WP_CLI) plugin install jetpack --version=14.3 --activate
	$(WP_CLI) plugin install the-events-calendar --version=6.15.16 --activate
	$(WP_CLI) option update users_can_register 1
	$(WP_CLI) option update default_role contributor
	$(WP_CLI) user create ${WORDPRESS_EDITOR_USER} ${WORDPRESS_EDITOR_EMAIL} --role=editor --user_pass=${WORDPRESS_EDITOR_PASSWORD} --porcelain || $(WP_CLI) user update ${WORDPRESS_EDITOR_USER} --user_pass=${WORDPRESS_EDITOR_PASSWORD} --user_email=${WORDPRESS_EDITOR_EMAIL} --role=editor
	$(WP_CLI) eval 'if ( class_exists( "Jetpack" ) && method_exists( "Jetpack", "activate_module" ) ) { Jetpack::activate_module( "shortcodes", false, false ); }'
	@chmod -R 555 /var/www/html/
	@sleep 1
	@chmod 444 /var/www/html/wp-config.php
