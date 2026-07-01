<?php
/**
 * Plugin Name: Plugin Custom
 * Description: Adds password fields to the default registration form.
*/

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

function plugin_custom_password_fields() {
	?>
	<p>
		<label for="pass1"><?php esc_html_e( 'Password' ); ?><br />
			<input type="password" name="pass1" id="pass1" class="input" value="" size="25" autocomplete="new-password" />
		</label>
	</p>
	<p>
		<label for="pass2"><?php esc_html_e( 'Confirm Password' ); ?><br />
			<input type="password" name="pass2" id="pass2" class="input" value="" size="25" autocomplete="new-password" />
		</label>
	</p>
	<?php
}
add_action( 'register_form', 'plugin_custom_password_fields' );

function plugin_custom_validate_passwords( $errors, $sanitized_user_login, $user_email ) {
	$pass1 = isset( $_POST['pass1'] ) ? (string) $_POST['pass1'] : '';
	$pass2 = isset( $_POST['pass2'] ) ? (string) $_POST['pass2'] : '';

	if ( '' === $pass1 || '' === $pass2 ) {
		$errors->add( 'password_empty', __( '<strong>Error:</strong> Please enter your password twice.' ) );
		return $errors;
	}

	if ( $pass1 !== $pass2 ) {
		$errors->add( 'password_mismatch', __( '<strong>Error:</strong> The passwords do not match.' ) );
	}

	return $errors;
}
add_filter( 'registration_errors', 'plugin_custom_validate_passwords', 10, 3 );

function plugin_custom_capture_password( $sanitized_user_login, $user_email, $errors ) {
	if ( ! empty( $errors->errors ) ) {
		return;
	}

	if ( isset( $_POST['pass1'] ) ) {
		$GLOBALS['plugin_custom_password'] = (string) $_POST['pass1'];
	}
}
add_action( 'register_post', 'plugin_custom_capture_password', 10, 3 );

function plugin_custom_set_user_password( $user_id ) {
	if ( empty( $GLOBALS['plugin_custom_password'] ) ) {
		return;
	}

	wp_set_password( $GLOBALS['plugin_custom_password'], $user_id );
	unset( $GLOBALS['plugin_custom_password'] );
}
add_action( 'user_register', 'plugin_custom_set_user_password' );

add_filter( 'wp_send_new_user_notification_to_admin', '__return_false' );

function plugin_custom_restrict_profile_page() {
	if ( ! is_admin() ) {
		return;
	}

	global $pagenow;

	if ( 'profile.php' !== $pagenow ) {
		return;
	}

	if ( current_user_can( 'manage_options' ) ) {
		return;
	}

	wp_die(
		esc_html__( 'You are not allowed to access this page.' ),
		403
	);
}
add_action( 'admin_init', 'plugin_custom_restrict_profile_page' );
