<!DOCTYPE html>
<html lang="en">

<head>
    <!-- Required meta tags-->
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta name="description" content="Napoli Blockchain">
    <meta name="author" content="Napoli Blockchain">
    <meta name="keywords" content="Napoli Blockchain">

    <!-- Progressive Web App -->
    <link rel="manifest" href="<?php echo Yii::app()->request->baseUrl; ?>/manifest.json">

        <!-- iOS -->
        <meta name="mobile-web-app-capable" content="yes">
        <meta name="apple-mobile-web-app-capable" content="yes">
        <meta name="apple-mobile-web-app-status-bar-style" content="black">
        <meta name="apple-mobile-web-app-title" content="<?php echo CHtml::encode($this->pageTitle); ?>">
        <link rel="apple-touch-icon" href="<?php echo Yii::app()->request->baseUrl; ?>/src/images/icons/apple-icon-76x76.png" sizes="76x76">
        <link rel="apple-touch-icon" href="<?php echo Yii::app()->request->baseUrl; ?>/src/images/icons/apple-icon-144x144.png" sizes="144x144">

        <!-- iExplorer -->
        <meta name="msapplication-TileImage" content="<?php echo Yii::app()->request->baseUrl; ?>/src/images/icons/apple-icon-144x144.png" sizes="144x144">
        <meta name="msapplication-TileColor" content="#fff">
        <meta name="theme-color" content="#3f51b5">

    <!-- Title Page-->
    <title><?php echo CHtml::encode($this->pageTitle); ?></title>

	<link rel="icon" href="<?php echo Yii::app()->request->baseUrl; ?>/css/images/favicon.ico" type="image/x-icon" />

    <!-- Fontfaces CSS-->
    <link href="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/css/font-face.css" rel="stylesheet" media="all">
    <link href="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/font-awesome-4.7/css/font-awesome.min.css" rel="stylesheet" media="all">
    <link href="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/font-awesome-5/css/fontawesome-all.min.css" rel="stylesheet" media="all">
    <link href="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/mdi-font/css/material-design-iconic-font.min.css" rel="stylesheet" media="all">

    <!-- Bootstrap CSS-->
    <link href="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/bootstrap-4.1/bootstrap.min.css" rel="stylesheet" media="all">

    <!-- Vendor CSS-->
    <link href="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/animsition/animsition.min.css" rel="stylesheet" media="all">
    <link href="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/bootstrap-progressbar/bootstrap-progressbar-3.3.4.min.css" rel="stylesheet" media="all">
    <link href="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/wow/animate.css" rel="stylesheet" media="all">
    <link href="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/css-hamburgers/hamburgers.min.css" rel="stylesheet" media="all">
    <link href="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/slick/slick.css" rel="stylesheet" media="all">
    <link href="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/select2/select2.min.css" rel="stylesheet" media="all">
    <link href="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/perfect-scrollbar/perfect-scrollbar.css" rel="stylesheet" media="all">

    <!-- Main CSS-->
    <link href="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/css/theme.css" rel="stylesheet" media="all">
    <link href="<?php echo Yii::app()->request->baseUrl; ?>/css/glyphicon.css" rel="stylesheet" media="all" >
    <link href="<?php echo Yii::app()->request->baseUrl; ?>/css/login.css" rel="stylesheet" media="all" >
    <link href="<?php echo Yii::app()->request->baseUrl; ?>/css/wallet.css" rel="stylesheet" media="all" >

    <!-- NUMPAD -->
    <link href="<?php echo Yii::app()->request->baseUrl; ?>/css/numpad/easy-numpad.css" rel="stylesheet" media="all" >

    <!-- NEW CSS-->
    <link href="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/css/lumen.css" rel="stylesheet" media="all">
    <!-- <link href="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/css/solar.css" rel="stylesheet" media="all"> -->

    <!-- Jquery JS-->
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/jquery-3.2.1.min.js"></script>
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/chartjs/Chart.bundle.min.js"></script>


    <!-- libs for my swiper function  -->
    <!-- <link href="<?php  //echo Yii::app()->request->baseUrl; ?>/src/jquery-ui/jquery-ui.min.css" rel="stylesheet" media="all" > -->
    <!-- <script src="<?php //echo Yii::app()->request->baseUrl; ?>/src/jquery-ui/jquery-ui.min.js"></script> -->
    <!-- <script src="<?php //echo Yii::app()->request->baseUrl; ?>/src/jquery-ui/jquery.ui.touch-punch.min.js"></script> -->


</head>

<body class="animsition">

            <div class="page-wrapper"  id='sfondo-login'>
                <!-- PAGE CONTAINER-->
                <div class="container">
                    <!-- MAIN CONTENT-->
                    <div id="page-vesuvio"></div>
                        <?php echo $content; ?>
                    <!-- END MAIN CONTENT-->
                <!-- END PAGE CONTAINER-->
                </div>
            </div>

    <!-- Bootstrap JS-->
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/bootstrap-4.1/popper.min.js"></script>
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/bootstrap-4.1/bootstrap.min.js"></script>

    <!-- Vendor JS       -->
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/slick/slick.min.js"></script>
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/wow/wow.min.js"></script>
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/animsition/animsition.min.js"></script>
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/bootstrap-progressbar/bootstrap-progressbar.min.js"></script>
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/counter-up/jquery.waypoints.min.js"></script>
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/counter-up/jquery.counterup.min.js"></script>
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/circle-progress/circle-progress.min.js"></script>
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/perfect-scrollbar/perfect-scrollbar.js"></script>
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/vendor/select2/select2.min.js"></script>

    <!-- Main JS-->
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/themes/cool/js/main.js"></script>

    <!-- call qrcode camera -->
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/protected/extensions/webcodecamjs-master/js/qrcodelib.js"></script>
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/protected/extensions/webcodecamjs-master/js/webcodecamjs.js"></script>

    <!-- Call Ethereum Wallet -->
    <!-- <script src="<?php //echo Yii::app()->request->baseUrl; ?>/src/ethjs/ethereumjs-wallet-0.6.0.min.js"></script> -->
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/src/ethjs/lightwallet.min.js"></script>
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/src/ethjs/aes.js"></script>
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/src/ethjs/aes-json-format.js"></script>

    <!-- call numpad -->
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/src/js/easy-numpad.js"></script>

    <!-- Gestione del Pin -->
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/src/js/pinutility.js"></script>

    <!-- Call Service Worker-->
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/src/js/promise.js"></script>
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/src/js/fetch.js"></script>
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/src/js/idb.js"></script>
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/src/js/utility.js"></script>
    <script src="<?php echo Yii::app()->request->baseUrl; ?>/src/js/service.js"></script>

</body>
</html>

<?php
include ('js_main.php');
?>


<!-- end document-->
