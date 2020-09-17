<?php
Yii::app()->language = ( isset($_COOKIE['lang']) ? $_COOKIE['lang'] : 'it' );
Yii::app()->sourceLanguage = ( isset($_COOKIE['langSource']) ? $_COOKIE['langSource'] : 'it_it' );
new JsTrans('js',Yii::app()->language); // javascript translation


$myCameraScript = <<<JS

//VIDEO CAMERA
var canvasElement = document.querySelector('#canvas');


$(function(){
	//al click del pulsante photo attivo la fotocamera
	$("button[id='activate-camera-btn']").click(function(){
		initializeMedia();
	});
});



/*
 * questa funzione inizializza i media a disposizione sul browser
 */
function initializeMedia() {
	console.log('Initialize media');
	canvasElement.style.display = 'block';

	var mediaCamera = {
		resultFunction: function(result) {
			console.log(result.code);
			$('#WalletTokenForm_to').val(result.code);
			$('#scrollmodalCamera').modal('hide');
			decoder.stop();
		}
	};
	//var decoder = new WebCodeCamJS("canvas").init(mediaCamera).play();
	var decoder = new WebCodeCamJS($('canvas')[0]).buildSelectMenu('#camera-select', 0).init(mediaCamera).play();
	decoder.options.constraints.facingMode = "environment";

	//al cambio di selezione attivo un'altra telecamera
	document.querySelector('#camera-select').addEventListener('change', function(){
     	decoder.stop().play();
    });
	document.querySelector('.camera-close').addEventListener('click', function(){
     	decoder.stop();
    });
}

JS;
Yii::app()->clientScript->registerScript('myCameraScript', $myCameraScript);
