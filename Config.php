<?php namespace Model\User;

use Model\Core\Module_Config;

class Config extends Module_Config
{
	protected function assetsList()
	{
		$this->addAsset('config', 'config.php', function () {
			return '<?php
$config = [
	\'algorithm-version\' => \'new\',
];
';
		});
	}

	/**
	 * @return bool
	 */
	public function postUpdate_2_0_0()
	{
		$directory = INCLUDE_PATH . 'app' . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'User';
		if (!is_dir($directory))
			mkdir($directory, 0755, true);
		file_put_contents($directory . DIRECTORY_SEPARATOR . 'config.php', '<?php
$config = [
	\'algorithm-version\' => \'old\',
];
');
		return true;
	}
}
