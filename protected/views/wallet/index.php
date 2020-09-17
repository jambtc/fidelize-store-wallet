<div class="warning-message">
	<?php
	if (null !== $warningmessage)
		foreach ($warningmessage as $message)
			echo $message;
	?>
</div>
<div class="form">
<?php
Yii::app()->language = ( isset($_COOKIE['lang']) ? $_COOKIE['lang'] : 'it' );
Yii::app()->sourceLanguage = ( isset($_COOKIE['langSource']) ? $_COOKIE['langSource'] : 'it_it' );
new JsTrans('js',Yii::app()->language); // javascript translation

$form=$this->beginWidget('CActiveForm', array(
	'id'=>'wallet-form',
	'enableAjaxValidation'=>false,
));

// integrazione per Istituti (Musei, ecc. ecc.)
$id_institute = Yii::app()->user->objUser['id_institute'];
if ($id_institute == 0){
	$walletForm->amount = null;
	$readonly = '';
}else{
	$walletForm->amount = Institutes::model()->findByPk($id_institute)->default_sending_quantity;
	$walletForm->memo = 'Omaggio '. Institutes::model()->findByPk($id_institute)->description;
	$readonly = 'readonly';
}
// end

//richiamo tutte le funzioni javascript
include ('js_pin.php');
include ('js_eth.php'); // viene prima di initiazlie
include ('js_walletInitialize.php');
include ('js_wallet.php');
include ('js_cgridview.php');

// include ('js_camera.php');
include ('js_qr-scanner.php');
include ('js_nfc.php');

$visible =  WebApp::isMobileDevice();


?>
<!-- MASCHERA PRINCIPALE -->
<div class='section__content section__content--p30'>
	<div class='container-fluid'>
		<!-- BALANCES VIEWS -->
		<div class="row">
			<div class="col-lg-6">
				<!-- <div class="card bg-transparent"> -->
				<div class="au-card au-card--no-shadow au-card--no-pad bg-overlay--semitransparent">
					<div class="card-header ">
						<i class="zmdi zmdi-balance"></i>
						<span class="card-title "><?php echo Yii::t('lang','Balance');?></span>
					</div>
					<div class="card-body">
							<div class="btn btn-primary" id="btnBalanceErc20" style="width:100%;">
								<h2>
								<strong><i class="zmdi zmdi-star-outline text-light"></i></strong>
								<strong><span class="balance-erc20 text-light"></span></strong>
								</h2>
							</div>

							<!-- <div class="btn btn-primary animationBalanceOut" id="btnBalanceEth" style="width:100%; display:none;">
								<h2>
								<i class="fab fa-ethereum text-primary"></i>
								<small><span class="balance-eth text-primary"></span></small>
								</h2>
							</div> -->
					</div>

					<div class="card-footer bg-transparent">
						<div class="row">
							<div style="width:100%; display:none;" class="sufee-alert with-close alert-dismissible fade show">
								<span class="badge badge-pill badge-danger"><?php echo Yii::t('lang','Error');?></span>
								<p id="errorMessage"></p>
								<button type="button" class="close" data-dismiss="alert" aria-label="Close">
									<span aria-hidden="true">×</span>
								</button>
							</div>
						</div>
						<?php $sendURL = Yii::app()->createUrl('wallettoken/send');	?>
						<center>
							<?php	if ($id_institute == 0){ ?>
								<button type="button" class="btn btn-success" data-toggle="modal" data-target="#scrollmodalRicevi" style="min-width:120px;"><?php echo Yii::t('lang','Receive');?></button>
							<?php } ?>
							<button type="button" class="btn btn-primary" data-toggle="modal" data-target="#scrollmodalInvia"  style="min-width:120px;"><?php echo Yii::t('lang','Send');?></button>
						</center>
					</div>
				</div>
			</div>
		</div>

		<!-- TRANSACTION VIEWS -->
		<div class="row">

			<div class="col-lg-12">
				</br></br>
			<div class="au-card au-card--no-shadow au-card--no-pad bg-overlay--semitransparent">
					<div class="card-header ">
						<i class="fa fa-star"></i>
						<span class="card-title"><?php echo Yii::t('lang','Transactions');?></span>
						<div class="show-rescan text-success">
							<div class="sync-blockchain float-right"></div>
							<div class="sync-difference"></div>
						</div>
					</div>
					<div class="card-body">
						<div class="table-responsive table--no-card m-b-30">
							<!-- <table class="table table-borderless table-striped table-earning"> -->
						<?php
						Yii::import('zii.widgets.grid.CGridView');
						class SpecialGridView extends CGridView {
							public $from_address;
						}
						$this->widget('SpecialGridView', array(
							'id' => 'tokens-grid',
							'hideHeader' => true,
							'htmlOptions' => array('class' => 'table table-borderless table-data4 table-wallet text-primary'),
						     'dataProvider'=>$modelc->search(),
							 'from_address'   => $from_address,          // your special parameter
							'pager'=>array(
						        //'header'=>'Go to page:',
						        //'cssFile'=>Yii::app()->theme->baseUrl
								'cssFile'=>Yii::app()->request->baseUrl."/css/yiipager.css",
						        'prevPageLabel'=>'<',
						        'nextPageLabel'=>'>',
						        'firstPageLabel'=>'<<',
						        'lastPageLabel'=>'>>',
						    ),

							'columns' => array(
								array(
									'type'=>'raw',
						            'name'=>'',
									'value'=>'WebApp::typeTransaction($data->type)',
									'htmlOptions'=>array('style'=>'width:1px;'),

						        ),

								array(
						            'name'=>'',
									'type'=>'raw',
									//'value' => 'CHtml::link(CHtml::encode(date("d/m/Y H:i:s",$data->invoice_timestamp)), Yii::app()->createUrl("wallet/details")."&id=".CHtml::encode(crypt::Encrypt($data->id_token)))',
									'value' => 'CHtml::link(WebApp::dateLN($data->invoice_timestamp,$data->id_token), Yii::app()->createUrl("tokens/view",["id"=>crypt::Encrypt($data->id_token)]) )',
									//'value' => 'CHtml::link(CHtml::encode(date("Y-m-d H:i:s",$data->invoice_timestamp)), Yii::app()->createUrl("tokens/view")."&id=".CHtml::encode(crypt::Encrypt($data->id_token)))',
									//'value' => 'crypt::Encrypt($data->id_token)<br>date("d/m/Y H:i:s",$data->invoice_timestamp)',


						        ),
								array(
									'type'=>'raw',
						            'name'=>'',
									'value'=>'CHtml::link(WebApp::walletStatus($data->status), Yii::app()->createUrl("tokens/view")."&id=".CHtml::encode(crypt::Encrypt($data->id_token)))',
									'cssClassExpression' => '( $data->status == "sent" ) ? "denied" : (( $data->status == "complete" ) ? "process" : "desc incorso")',
						        ),
								array(
									'type'=>'raw',
						            'name'=>'',
									'value'=>'WebApp::typePrice($data->token_price,(($data->from_address == $this->grid->from_address) ? "sent" : "received"))',
									'htmlOptions'=>array('style'=>'text-align:center;'),
						        ),

								// [
								// 	'type'=>'raw',
						        //     'name'=>'fiat_price',
								// 	'value'=>'$data->fiat_price',
								// 	'visible'=>!$visible,
						        // ],
								//
								// [
								// 	'type'=>'raw',
						        //     'name'=>'rate',
								// 	'value'=>'$data->rate',
								// 	'visible'=>!$visible,
						        // ],
								[
									'type'=>'raw',
									'name'=>'from_address',
									'value'=>'CHtml::link(($data->from_address == $this->grid->from_address ? $data->to_address : $data->from_address), Yii::app()->createUrl("tokens/view")."&id=".CHtml::encode(crypt::Encrypt($data->id_token)))',
									'visible'=>!$visible,
								],

								array(
									'type'=>'raw',
									'name'=>'',
									'value'=>'WebApp::isConfirmedLock('.$actualBlockNumberDec.',$data->blocknumber)',
									'htmlOptions'=>array('style'=>'width:50px;'),

								),
							)
						));
						?>
						</div>
					</div>
				</div>
			</div>
		</div>
		</div>
			<?php echo Logo::footer(); ?>
	</div>
</div>

<!-- CONFERMA INVIO TOKEN -->
<div class="modal fade" id="scrollmodalGas" tabindex="-1" role="dialog" aria-labelledby="scrollmodalLabel" style="display: none;" aria-hidden="true">
	<div class="modal-dialog modal-lg" role="document">
		<div class="modal-content ">
			<div class="modal-header">
				<h3 class="modal-title" id="scrollmodalLabel"><?php echo Yii::t('lang','Confirm Token Send');?></h3>
				<button type="button" class="close" data-dismiss="modal" aria-label="Close">
					<span aria-hidden="true">×</span>
				</button>
			</div>
			<div class="modal-body">
				<!-- <div class="card"> -->
					<!-- <div class="card-header"  style="font-size:2em;"> -->
						<!-- <strong class="card-title mb-3">Balance: <span class="badge badge-light"><span class="mt-1 balance-erc20"></span></span></strong>
						<i class="zmdi zmdi-star-outline"></i> -->
					<!-- </div> -->
					<!-- <div class="form-group">

						<h4 class="card-title mb-3">Balance: </h4>
					</div> -->
					<!-- <div class="card-body"> -->

						<div class="alert-light ">
							<div class="table-responsive">
								<table class="table table-borderless table-wallet text-primary">
									<tbody>
										<tr>
											<input type="hidden" id="balance-erc20" />
											<input type='hidden' id='gasPrice' value=0 />
											<td><?php echo Yii::t('lang','Availability');?>:</td>
											<td><span class="text-success"><span class="mt-1 balance-erc20"></span></span></td>
										</t>
										<tr>
											<td><?php echo Yii::t('lang','Send');?>:</td>
											<td><span id='amount' class="text-success"></span></td>
										</tr>

										<tr>
											<td><?php echo Yii::t('lang','Availability after sending');?>:</td>
											<td><span id='totale' class="text-success"></span></td>
										</tr>
										<tr>
											<td colspan=3>
												<!-- MESSAGGIO -->
												<div class="form-group">
													<small class="form-text text-muted"><?php echo $form->labelEx($walletForm,'memo', array('class'=>'text-primary')); ?></small>
													<div class="input-group">
														<?php echo $form->textArea($walletForm,'memo',array('maxlength' => 300, 'rows' => 6, 'cols' => 50, 'class'=>'form-control','readonly'=>$readonly)); ?>
													</div>
													<div class="invalid-feedback" id="WalletForm_memo_em_" style="display:none"></div>
												</div>
											</td>
										</tr>

										<!-- ESEMPIO DI SWITCH -->
										<!-- <tr>
											<td colspan="2" style="padding: 0px;">
												<table class="table table-borderless table-wallet">
													<tr class="alert alert-secondary">
														<td>
															<p class="text-primary"><?php //echo Yii::t('lang','Transaction cost');?>:</p>
															<p class="text-primary" id='gassing-text'><?php //echo Yii::t('lang','Standard');?></p>
														</td>
														<td>
															<p id='gasPrice' class="text-danger"></p>
															<p>
																<label class="switch switch-3d switch-danger mr-3">
																	<input type="checkbox" class="switch-input" id='gassing-value' >
																	<span class="switch-label"></span>
																	<span class="switch-handle"></span>
											                    </label>
															</p>
														</td>
													</tr>
												</table>
											</td>
										</tr> -->
									</tbody>
								</table>
							</div>
							<div style="width:100%; display:none;" class="sufee-alert with-close alert-dismissible fade show">
								<span class="badge badge-pill badge-danger"><?php echo Yii::t('lang','Error');?></span>
								<p id="errorMessageOnSend"></p>
								<button type="button" class="close" data-dismiss="alert" aria-label="Close">
									<span aria-hidden="true">×</span>
								</button>
							</div>

						</div>

					<!-- </div> -->
				<!-- </div> -->
			</div>
			<div class="modal-footer">
				<button type="button" class="btn btn-secondary" data-dismiss="modal"><?php echo Yii::t('lang','back');?></button>
				<button type="button" class="btn btn-primary" name='tokenConfirm' id='tokenConfirm' onclick=""><?php echo Yii::t('lang','confirm');?></button>
				<button type="button" class="btn btn-secondary" data-dismiss="modal" id='tokenConfirmOk' style="display:none;"><?php echo Yii::t('lang','close');?></button>
			</div>

		</div>
	</div>
</div>


<!-- MASCHERA INSERIMENTO DATI INVIO TOKEN -->
<div class="modal fade" id="scrollmodalInvia" tabindex="-1" role="dialog" aria-labelledby="scrollmodalLabel" style="display: none;" aria-hidden="true">
	<div class="modal-dialog modal-lg" role="document">
		<div class="modal-content">
			<div class="modal-header">
				<h3 class="modal-title" id="scrollmodalLabel"><?php echo Yii::t('lang','Send');?></h3>
				<button type="button" class="close" data-dismiss="modal" aria-label="Close">
					<span aria-hidden="true">×</span>
				</button>
			</div>
			<div class="modal-body">
				<div class="form-group">
					<h4 class="card-title mb-3"><?php echo Yii::t('lang','Balance');?>: <i class="zmdi zmdi-star-outline"></i> <span class="text-success"><span class="mt-1 balance-erc20"></span></span></h4>
				</div>
				<!-- DA -->
				<div class="form-group">
					<!-- BUGFIX x Chrome che riempie in automatico i campi successivi -->
					<input style="display:none">
					<input type="password" style="display:none">
					<!-- end bugfix -->
					<?php $walletForm->from = $from_address; ?>
					<?php	if ($id_institute == 0){ ?>
						<small class="form-text text-muted"><?php echo $form->labelEx($walletForm,'from', array('class'=>'text-primary')); ?></small>
						<div class="input-group">
							<?php echo $form->textField($walletForm,'from',array('size'=>60,'maxlength'=>250,'class'=>'form-control f05','disabled'=>'disabled')); ?>
						</div>
					<?php }else{
							echo $form->hiddenField($walletForm,'from',array('size'=>60,'maxlength'=>250,'class'=>'form-control f05','disabled'=>'disabled'));
					}
					?>

					<div class="invalid-feedback" id="WalletForm_from_em_" style="display:none"></div>
				</div>
				<!-- A -->
				<div class="form-group">
					<small class="form-text text-muted"><?php echo $form->labelEx($walletForm,'to', array('class'=>'text-primary')); ?></small>
					<div class="input-group">
						<button style='display:none;' type='button' class="btn btn-primary" id="activate-contacts-btn" data-toggle="modal" data-target="#scrollmodalContacts"><i class="fa fa-users"></i></button>
						<?php echo $form->textField($walletForm,'to',array('size'=>60,'maxlength'=>250,'class'=>'form-control f05', 'autocomplete' => 'off')); ?>
						<button type='button' class="btn btn-light" id="activate-nfc-btn" data-toggle="modal" data-target="#scrollmodalNFC" style="padding: 0px 5px 0px 5px;">
							<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24">
								<path d="M20 2H4c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 18H4V4h16v16zM18 6h-5c-1.1 0-2 .9-2 2v2.28c-.6.35-1 .98-1 1.72 0 1.1.9 2 2 2s2-.9 2-2c0-.74-.4-1.38-1-1.72V8h3v8H8V8h2V6H6v12h12V6z"/>
							</svg>
						</button>
						<button type='button' class="btn btn-primary" id="activate-camera-btn" data-toggle="modal" data-target="#scrollmodalCamera">
							<i class="fa fa-camera"></i>
						</button>
					</div>
					<div class="invalid-feedback" id="WalletForm_to_em_" style="display:none"></div>
				</div>
				<!-- IMPORTO -->
				<div class="form-group">
					<small class="form-text text-muted"><?php echo $form->labelEx($walletForm,'amount', array('class'=>'text-primary')); ?></small>
					<div class="input-group">
						<?php echo $form->numberField($walletForm,'amount',array('size'=>60,'maxlength'=>250,'class'=>'form-control f05','readonly'=>$readonly)); ?>
					</div>
					<?php $walletForm->amount = 0; ?>
					<div class="invalid-feedback" id="WalletForm_amount_em_" style="display:none"></div>
				</div>
			</div>
			<!-- <div class="card-body-numpad"></div> -->
			<div class="modal-footer">
				<button type="button" class="btn btn-secondary" data-dismiss="modal"><?php echo Yii::t('lang','back');?></button>
				<button type="button" class="btn btn-primary" name='tokenAvanti' id='tokenAvanti' onclick=""><?php echo Yii::t('lang','go on...');?></button>
			</div>
		</div>

	</div>
</div>




<!-- MOSTRA SCANSIONE NFC -->
<div class="modal fade" id="scrollmodalNFC" tabindex="-1" role="dialog" aria-labelledby="scrollmodalLabelNFC" style="display: none;" aria-hidden="true">
	<div class="modal-dialog modal-lg" role="document">
		<div class="modal-content alert-dark">
			<div class="modal-header">
				<h3 class="modal-title text-light" id="scrollmodalLabelNFC"><?php echo Yii::t('lang','NFC');?></h3>
				<button type="button" class="close" data-dismiss="modal" aria-label="Close">
					<span aria-hidden="true">×</span>
				</button>
			</div>
			<div class="modal-body">
				<p style="text-align:center;">
					<img src="css/images/nfc_white_192x192.png" width="256" height="256" />
				</p>
			</div>
			<div class="modal-footer">
				<button type="button" class="btn btn-secondary" id='nfc-close' data-dismiss="modal" style="min-width: 100px; padding:2.5px 10px 2.5px 10px; height:30px;">
					<i class="fa fa-reply"></i> <?php echo Yii::t('lang','close');?>
				</button>
			</div>
		</div>
	</div>
</div>


<!-- MOSTRA FOTOCAMERA PER SCANSIONE QR-CODE -->
<div class="modal fade" id="scrollmodalCamera" tabindex="-1" role="dialog" aria-labelledby="scrollmodalLabelCamera" style="display: none;" aria-hidden="true">
	<div class="modal-dialog modal-lg" role="document">
		<div class="modal-content alert-dark text-light">
			<div class="modal-body" id='camera-body'>
				<center>
					<div id="video-content">
					    <video muted playsinline id="qr-video"></video>
						<div id='rounded-box'>&nbsp;</div>
					</div>
				</center>
			</div>
			<div class="modal-footer">
				<button type="button" class="btn btn-secondary btn-sm" data-dismiss="modal" id='camera-close'><?php echo Yii::t('lang','close');?></button>
			</div>
		</div>
	</div>
</div>





<!-- SCELTA INIZIALE DI RIPRISTINO O NUOVO WALLET -->
<div class="modal fade" id="initializeWallet" tabindex="-1" role="dialog" aria-labelledby="choiceModalLabel" aria-hidden="true" style="display: none;">
	<div class="modal-dialog modal-lg" role="document">
		<div class="modal-content alert-light text-primary">
			<div class="modal-body">
				<div class="typo-headers">
					<h3 class="text-primary"><?php echo Yii::t('lang','Hi,');?></h3>
				</div>
				<div class="typo-articles">
					<p class="text-yellow">
						<?php
						echo Yii::t('lang','soon you will activate your new TTS wallet, so you will be able to receive and send tokens (discount coupons) among the activities participating in the project.');
						echo "<br>";
						echo Yii::t('lang','Your electronic wallet will be made secure thanks to a mathematical process that will make the content unreadable.');
						echo "<br>";
						echo Yii::t('lang','So, 12 words will be chosen that uniquely identify your wallet. The merit is of cryptography, in particular of the hierarchical deterministic concept, which, thanks to the use of some mathematical functions, allows users, starting from the seed, to recover everything.');
						?>
					</p>
					<p class="text-yellow">
						<?php echo Yii::t('lang','These random words will be unique in the world and will allow you to recover the contents of your wallet even in case of loss of your device.'); ?>
					</p>
					<p class="text-yellow"><b>
						<?php echo Yii::t('lang','But be careful, keep them in a safe place \'cause anyone who gets hold of this key can access its contents.');?>
						</b>
					</p>
					<p><b>
						<?php echo Yii::t('lang','Remember to make a backup of your digital wallet. This is an important step in securing your asset.');?>
						</b>
					</p>

					<p><?php echo Yii::t('lang','If you already have a mnemonic key (seed) and want to restore your old wallet, press the button <i><b>"Restore"</b></i>');?></p>
					<p><?php echo Yii::t('lang','If you want to generate a new digital wallet, click on the <i><b>"New"</b> </i> button and follow the recommended instructions.');?></p>
					<p><?php echo Yii::t('lang','If you want to exit, click on the <i><b>"Logout"</b> </i> button.');?></p>

					<button type="button" style="padding:2.5px 10px 2.5px 10px; height:30px;" class="btn alert-primary text-light" data-toggle="modal" data-dismiss="modal" id="CalloldSeedModal" style="min-width:120px;">
						<i class="fas fa-repeat"></i> <?php echo Yii::t('lang','Restore');?>
					</button>
					<button type="button" style="padding:2.5px 10px 2.5px 10px; height:30px;" class="btn alert-primary text-light" data-toggle="modal" data-dismiss="modal" style="min-width:120px;" id='newWallet'>
						<i class="fas fa-key"></i> <?php echo Yii::t('lang','New');?>
					</button>

					<div class="float-right">
						<?php $actionURL = Yii::app()->createUrl('site/logout'); ?>
						<a href="<?php echo $actionURL;?>">
							<button class="btn alert-primary text-light" style="padding:2.5px 10px 2.5px 10px; height:30px;">
								<i class="fas fa-sign-out-alt"></i> <?php echo Yii::t('lang','Logout');?></button>
						</a>
					</div>
				</div>
			</div>
		</div>
	</div>
</div>

<!-- GENERAZIONE NUOVO SEED -->
<div class="modal fade" id="seedModal" tabindex="-1" role="dialog" aria-labelledby="seedModalLabel" aria-hidden="true" style="display: none;">
	<div class="modal-dialog modal-lg" role="document">
		<div class="modal-content">
			<div class="modal-body">
				<h3><?php echo Yii::t('lang','Your new seed is:');?></h3>
				<p id='seedText'></p>
				<input type='hidden' id='seedInput' />
			</div>
			<div class="modal-footer">
				<button type="button" class="btn btn-secondary" data-dismiss="modal" name="cryptIndietro"><?php echo Yii::t('lang','Back');?></button>
				<button type="button" class="btn btn-primary" data-dismiss="modal" data-toggle="modal" data-target="#repeatSeedModal" style="min-width:90px;"><?php echo Yii::t('lang','Next');?></button>
			</div>
		</div>
	</div>
</div>

<!-- RIPETI NUOVO SEED -->
<div class="modal fade" id="repeatSeedModal" tabindex="-1" role="dialog" aria-labelledby="repeatSeedModalLabel" aria-hidden="true" style="display: none;" >
	<div class="modal-dialog modal-lg" role="document">
		<div class="modal-content">
			<div class="modal-body">
				<h3><?php echo Yii::t('lang','Verify Seed');?></h3>
				<p><?php echo Yii::t('lang','Please, insert your seed.');?></p>
				<textarea id='repeat_seed' class='form-control' /></textarea>
				<div class="invalid-feedback" id="repeat_seed_em_" ></div>
			</div>
			<div class="modal-footer">
				<button type="button" class="btn btn-secondary" data-dismiss="modal" name="confirmIndietro" ><?php echo Yii::t('lang','back');?></button>
				<button type="button" class="btn btn-primary" id='cryptConferma' style="min-width:90px;"><?php echo Yii::t('lang','Confirm');?></button>
			</div>
		</div>
	</div>
</div>

<!-- INSERIMENTO VECCHIO SEED -->
<div class="modal fade" id="oldSeedModal" tabindex="-1" role="dialog" aria-labelledby="oldSeedModalLabel" aria-hidden="true" style="display: none;" >
	<div class="modal-dialog modal-lg" role="document">
		<div class="modal-content alert-light text-primary">
			<div class="modal-body">
				<h3 class="text-primary"><?php echo Yii::t('lang','Restore');?></h3>
				<p class="text-primary"><?php echo Yii::t('lang','Insert your seed to restore the wallet.');?></p>
				<textarea id='old_seed' class='form-control' /></textarea>
				<div class="invalid-feedback" id="old_seed_em_" ></div>
			</div>
			<div class="modal-footer">
				<button type="button" class="btn btn-secondary" data-dismiss="modal" name="cryptIndietro"><?php echo Yii::t('lang','back');?></button>
				<button type="button" class="btn btn-primary" id='oldSeedConferma' style="min-width:90px;"><?php echo Yii::t('lang','Confirm');?></button>
			</div>
		</div>
	</div>
</div>

<!-- MOSTRA QRCODE DI RICEZIONE -->
<div class="modal fade" id="scrollmodalRicevi" tabindex="-1" role="dialog" aria-labelledby="scrollmodalLabelRicevi" style="display: none;" aria-hidden="true">
	<div class="modal-dialog modal-lg" role="document">
		<div class="modal-content alert-light text-primary">
			<div class="modal-header">
				<h3 class="modal-title" id="scrollmodalLabelRicevi"><?php echo Yii::t('lang','Receive');?></h3>
				<button type="button" class="close" data-dismiss="modal" aria-label="Close">
					<span aria-hidden="true">×</span>
				</button>
			</div>
			<div class="modal-body">
				<div class="payment-box alert-light">
					<div id="scan" class="bp-view payment scan active">
						<div class="payment__scan">
							<?php

							$this->widget('application.extensions.qrcode.QRCodeGenerator',array(
								'data' => $from_address,
								'filename' => $from_address . '.png',
								'filePath' => Yii::app()->basePath . '/qrcodes/',
								'subfolderVar' => false,
								'displayImage'=>true, // default to true, if set to false display a URL path
								'errorCorrectionLevel'=>'H', // available parameter is L,M,Q,H
								'matrixPointSize'=>6, // 1 to 10 only
							));
							?>
						</div>
					</div>
				</div>
				<div class="col copyonClickAddress">
					<div class="alert alert-secondary">
						<center>
							<small style="word-wrap: break-word;" class="copyWalletAddress">
								<?php echo $from_address; ?>
							</small>
							<input type="hidden" readonly="readonly" id="inputcopyWalletAddress" value="<?php echo $from_address; ?>" />
						</center>
					</div>
				</div>
				<div class="alert alert-warning" style='display:none;' id="statusNFC"></div>
			</div>
			<div class="modal-footer">
				<button type="button" class="btn btn-secondary" data-dismiss="modal" style="min-width:100px; padding:2.5px 10px 2.5px 10px; height:30px;">
					<i class="fa fa-reply"></i> <?php echo Yii::t('lang','close');?>
				</button>
				<button type="button" class="btn alert-primary text-light" name='NFCwriteButton' id='NFCwriteButton' style="min-width:100px; padding:2.5px 10px 2.5px 10px; height:30px;">
					<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24">
						<path d="M20 2H4c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 18H4V4h16v16zM18 6h-5c-1.1 0-2 .9-2 2v2.28c-.6.35-1 .98-1 1.72 0 1.1.9 2 2 2s2-.9 2-2c0-.74-.4-1.38-1-1.72V8h3v8H8V8h2V6H6v12h12V6z"/>
					</svg> <?php echo Yii::t('lang','NFC');?>
				</button>

			</div>

		</div>
	</div>
</div>

<!-- modal di copia in clipboard -->
<div class="modal fade" id="copyAddressModal" tabindex="-1" role="dialog" aria-labelledby="copyAddressModalLabel" aria-hidden="true" style="display: none;" >
	<div class="modal-dialog modal-sm" role="document">
		<div class="modal-content alert-info text-primary">
			<div class="modal-header">
				<h5 class="modal-title" id="copyAddressModalLabel"><?php echo Yii::t('lang','Copied');?></h5>
				<button type="button" class="close" data-dismiss="modal" aria-label="Close">
					<span aria-hidden="true">×</span>
				</button>
			</div>
			<div class="modal-body">
				<small  style="word-wrap: break-word;"><?php echo $from_address; ?></small>
			</div>
		</div>
	</div>
</div>

<!-- RICHIESTA PIN -->
<div class="modal fade " id="pinRequestModal" tabindex="-1" role="dialog" aria-labelledby="pinRequestModalLabel" aria-hidden="true" style="display: none;">
    <div class="modal-dialog modal-sm" role="document">
		<div class="modal-content alert-light text-primary ">
			<div class="modal-header">
				<h5 class="modal-title" id="pinRequestModalLabel"><?php echo Yii::t('lang','PIN Request');?></h5>
			</div>
			<div class="modal-body ">
				<center>
					<input type='hidden' id='pin_password' class='form-control' readonly="readonly"/>
                    <input type='hidden' id='pin_password_confirm' class='form-control' readonly="readonly"/>
                </center>
                <div class="pin-confirm-numpad pin-newframe-numpad"></div>
			</div>
			<div class="modal-footer">
				<div class="form-group">
					<button type="button" disabled="disabled" class="btn btn-primary disabled" id="pinRequestButton"><?php echo Yii::t('lang','Confirm');?></button>
				</div>
			</div>
		</div>
	</div>
</div>


<?php $this->endWidget(); ?>
</div><!-- form -->
