<?php

/**
 * This is the model class for table "np_contacts".
 *
 * The followings are the available columns in table 'np_contacts':
 * @property integer $id_contact
 * @property integer $id_user
 * @property integer $id_social
 */
class Contacts extends CActiveRecord
{
	public $username;
	/**
	 * @return string the associated database table name
	 */
	public function tableName()
	{
		return 'bolt_contacts';
	}

	/**
	 * @return array validation rules for model attributes.
	 */
	public function rules()
	{
		// NOTE: you should only define rules for those attributes that
		// will receive user inputs.
		return array(
			//array('id_user, telegram_id', 'required'),
			array('id_user, id_social', 'numerical', 'integerOnly'=>true),

			array('username','countLength'),

			// The following rule is used by search().
			// @todo Please remove those attributes that should not be searched.
			array('id_contact, id_user, id_social', 'safe', 'on'=>'search'),
		);
	}

	public function countLength($attribute,$params)
	{
		if (strlen($this->username) <3 ){
			$this->addError($attribute,'Enter at least three characters.');
		}
	}

	/**
	 * @return array relational rules.
	 */
	public function relations()
	{
		// NOTE: you may need to adjust the relation name and the related
		// class name for the relations automatically generated below.
		return array(
		);
	}

	/**
	 * @return array customized attribute labels (name=>label)
	 */
	public function attributeLabels()
	{
		return array(
			'id_contact' => Yii::t('model','Id Contact'),
			'id_user' => Yii::t('model','Id User'),
			'username' => Yii::t('model','Username'),
			'id_social' => Yii::t('model','id_social'),
		);
	}

	/**
	 * Retrieves a list of models based on the current search/filter conditions.
	 *
	 * Typical usecase:
	 * - Initialize the model fields with values from filter form.
	 * - Execute this method to get CActiveDataProvider instance which will filter
	 * models according to data in model fields.
	 * - Pass data provider to CGridView, CListView or any similar widget.
	 *
	 * @return CActiveDataProvider the data provider that can return the models
	 * based on the search/filter conditions.
	 */
	public function search()
	{
		// @todo Please modify the following code to remove attributes that should not be searched.

		$criteria=new CDbCriteria;

		$criteria->compare('id_contact',$this->id_contact);
		$criteria->compare('id_user',$this->id_user);
		$criteria->compare('id_social',$this->id_social,true);

		return new CActiveDataProvider($this, array(
			'criteria'=>$criteria,
		));
	}

	/**
	 * Returns the static model of the specified AR class.
	 * Please note that you should have this exact method in all your CActiveRecord descendants!
	 * @param string $className active record class name.
	 * @return Contacts the static model class
	 */
	public static function model($className=__CLASS__)
	{
		return parent::model($className);
	}
}
