<?php

/**
 * UserIdentity represents the data needed to identity a user.
 * It contains the authentication method that checks if the provided
 * data can identity the user.
 */
class UserIdentity extends CUserIdentity
{
	const ERROR_USERNAME_NOT_ACTIVE = 3;
	const ERROR_USERNAME_NOT_MEMBER = 4;
	const ERROR_GOOGLE_NOT_AUTHENTICATE = 5;
	const ERROR_GOOGLE_NOT_ENABLED = 6;

	private $_id;
	/**
	 * Authenticates a user.
	 * The example implementation makes sure if the username and password
	 * are both 'demo'.
	 * In practical applications, this should be changed to authenticate
	 * against some persistent user identity storage (e.g. database).
	 * @return boolean whether authentication succeeds.
	 */
	public function authenticate()
	{
		// CREO IL PRIMO HASH DI UNA PASSWORD
		// $hash = CPasswordHelper::hashPassword($this->password);
		// echo $hash;
		// exit;
		#echo "<pre>".print_r($_POST,true)."</pre>";
		#exit;

		$save = new Save;

		//Creo la query
		$record=Users::model()->findByAttributes(array('email'=>$this->username));


		if($record===null){
			$this->errorCode=self::ERROR_USERNAME_INVALID;
			$save->WriteLog('wallet-tts','useridentity','authenticate','Incorrect username: '.$this->username);
		}
		else if(!CPasswordHelper::verifyPassword($this->password,$record->password)){
			$this->errorCode=self::ERROR_PASSWORD_INVALID;
			$save->WriteLog('wallet-tts','useridentity','authenticate','Incorrect password for user: '.$this->username);
		}
		else if($record->status_activation_code == 0){
		 	$this->errorCode=self::ERROR_USERNAME_NOT_ACTIVE;
			$save->WriteLog('wallet-tts','useridentity','authenticate','User not active: '.$this->username);
		}
		else
		{
			$valid = true;
			// Per rendere facoltativo il 2fa, verifico prima che il campo sia riempito
			// In caso positivo attivo il 2fa, altrimenti proseguo...
			if (null !== $record->ga_secret_key){
				//verifico che OTP di google authenticator sia passato correttamente
				$key = CHtml::encode($_POST['LoginForm']['ga_cod']);
				$ga = new GoogleAuthenticator();

				$checkResult = $ga->verifyCode($record->ga_secret_key, $key, 2);    // 2 = 2*30sec clock tolerance
				if (!$checkResult){
					$this->errorCode=self::ERROR_GOOGLE_NOT_AUTHENTICATE;
					$valid = false;
				}
			}

			if ($valid){
				//altrimenti, prosegue...
				$this->_id=$record->id_user;
				//$this->setState('title', $record->title);
				$this->errorCode=self::ERROR_NONE;

				// Carico lo user type e la descrizione e l'assegno all'array di stato objUser
				$UsersType = new UsersType;

				$UserDesc=CHtml::listData($UsersType::model()->findAll(),'id_users_type','desc');
				$UserPrivileges=CHtml::listData($UsersType::model()->findAll(),'id_users_type','status');

				// social user parameters
				$social = Socialusers::model()->findByAttributes([
					'email'=>$this->username,
					'oauth_provider'=>'merchant', // il provider social per i commercianti
				]);
				if (null === $social){
					$social = new Socialusers;
				}
				$emptysocial = explode('@',$record->email);

				$save->WriteLog('wallet-tts','useridentity','authenticate','User '.$this->username. ' logged in.');

				$id_institute = 0;

				$this->setState('objUser', array(
					'id_user' => $record->id_user,
					'name' => $record->name,
					'surname' => $record->surname,
					'email' => $record->email,
					'ruolo' => $UserDesc[$record->id_users_type],
					'privilegi' => $UserPrivileges[$record->id_users_type],
					'facade' => 'dashboard',
					// bolt integration
					'username' => (empty($social->username) ? $emptysocial[0] : $social->username),
					'picture' => (empty($social->picture) ? 'css/images/anonymous.png' : $social->picture),
					'provider'=> 'merchant', //così evito errori in caso di socialuser inesistente
					// institute integration
					'id_institute' => $id_institute,
				));
			}
		}
		return !$this->errorCode;
	}
}
