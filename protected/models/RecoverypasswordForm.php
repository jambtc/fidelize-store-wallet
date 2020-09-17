<?php

/**
 * LoginForm class.
 * LoginForm is the data structure for keeping
 * user login form data. It is used by the 'login' action of 'SiteController'.
 */
class RecoverypasswordForm extends CFormModel
{
	public $username;
	public $password;
	public $oauth_provider;
	public $reCaptcha;
	//public $verifyCode;

	private $_identity;

	/**
	 * Declares the validation rules.
	 * The rules state that username and password are required,
	 * and password needs to be authenticated.
	 */


	public function rules()
	{
		if (gethostname()=='CGF6135T'){
			$array = array(
				// username and password are required
				array('username, password', 'required'),

				// password needs to be authenticated
				array('username,password', 'authenticateEMAIL'),
				// secret is required
				array('reCaptcha ', 'required'),
			);
		}else{
			$array = array(
				// username and password are required
				array('username, password', 'required'),

				// password needs to be authenticated
				array('username,password', 'authenticateEMAIL'),
				// secret is required
				array('reCaptcha ', 'required'),
				array('reCaptcha', 'application.extensions.reCaptcha2.SReCaptchaValidator', 'secret' => Yii::app()->params['reCaptcha2PrivateKey'],'message' => 'The verification code is incorrect.'),
				//array('verifyCode', 'captcha', 'allowEmpty'=>!CCaptcha::checkRequirements()),
			);

		}
		return $array;
	}

	/**
	 * Declares attribute labels.
	 */
	public function attributeLabels()
	{
		return array(
			'username'=>Yii::t('model','Email'),
		);
	}

	/**
	 * Authenticates the password.
	 * This is the 'authenticate' validator as declared in rules().
	 * @param string $attribute the name of the attribute to be validated.
	 * @param array $params additional parameters passed with rule when being executed.
	 */
	public function authenticateEMAIL($attribute,$params)
	{
		if(!$this->hasErrors())
		{
			$this->_identity=new EMAILIdentity($this->username,$this->password);
			if(!$this->_identity->authenticateEMAIL())
			 	$this->addError('username',Yii::t('model','No email found.'));
		}
	}

	/**
	 * Logs in the user using the given username and password in the model.
	 * @return boolean whether login is successful
	 */
	public function login()
	{
		if($this->_identity===null)
		{
			$this->_identity=new EMAILIdentity($this->username);
			$this->_identity->authenticateEMAIL();
		}
		if($this->_identity->errorCode===EMAILIdentity::ERROR_NONE)
		{
			$duration=0; 3600*24*30; // 30 days
			Yii::app()->user->login($this->_identity,$duration);
			return true;
		}
		else
			return false;
	}
}
