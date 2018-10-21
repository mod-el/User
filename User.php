<?php namespace Model\User;

use Model\Core\Module;

class User extends Module
{
	/** @var array */
	public $options = [];

	/**
	 * @param array|string $options
	 */
	public function init(array $options)
	{
		$config = $this->retrieveConfig();
		$options = array_merge($config, $options);
		$this->options = array_merge([
			'table' => 'users',
			'primary' => 'id',
			'username' => 'username',
			'password' => 'password',
			'old_password' => null,
			'filters' => [],
			'mandatory' => false,
			'affected-modules' => ['Router'],
			'except' => [],
			'login-controller' => 'Login',
			'algorithm-version' => 'new',
			'old-crypt-function' => function (string $pass): string {
				return sha1(md5($pass));
			},
			'old-verify-function' => function (string $pass, string $hash): bool {
				return ($hash === sha1(md5($pass)));
			},
			'crypt-function' => function (string $pass): string {
				return password_hash($pass, PASSWORD_DEFAULT);
			},
			'verify-function' => function (string $pass, string $hash): bool {
				return password_verify($pass, $hash);
			},
		], $options);

		if (!$this->model->isCLI())
			$this->cookieLogin();

		$this->model->on('Core_controllerFound', function ($data) {
			$this->checkMandatory($data['controller']);
		}, true);
	}

	/**
	 * @param string $username
	 * @param string $password
	 * @param bool $remember
	 * @param array $filters
	 * @return bool|int
	 */
	public function login(string $username, string $password, bool $remember = true, array $filters = [])
	{
		if ($this->options['table'] === false)
			return false;
		$this->logout();

		$filters = array_merge($this->options['filters'], $filters);
		$where = array_merge($filters, [
			$this->options['username'] => $username,
		]);

		$user = $this->model->_Db->select($this->options['table'], $where);
		if ($user) {
			$verified = false;
			switch ($this->options['algorithm-version']) {
				case 'old':
					$verified = $this->options['old-verify-function']($password, $user[$this->options['password']]);
					break;
				case 'new':
					if ($this->options['old_password'] and $user[$this->options['old_password']]) {
						$verified = $this->options['old-verify-function']($password, $user[$this->options['old_password']]);
						if ($verified) {
							$new_password = $this->options['crypt-function']($password);
							$this->model->_Db->update($this->options['table'], $user[$this->options['primary']], [
								$this->options['password'] => $new_password,
								$this->options['old_password'] => '',
							]);
						}
					} else {
						$verified = $this->options['verify-function']($password, $user[$this->options['password']]);
					}
					break;
			}
			if ($verified)
				return $this->directLogin($user, $remember);
			else
				return false;
		} else {
			return false;
		}
	}

	/**
	 * @param int|array $user
	 * @param bool $remember
	 * @return bool|int
	 */
	public function directLogin($user, bool $remember = true)
	{
		if ($this->options['table'] === false)
			return false;
		if ($this->model->isCLI())
			$remember = false;

		$n = $this->module_id;

		if (is_numeric($user)) {
			$user = $this->model->_Db->select($this->options['table'], [
				$this->options['primary'] => $user,
			]);
			if (!$user)
				return false;
		}

		$_SESSION[SESSION_ID]['user-' . $n] = $user;
		if ($remember) {
			setcookie('user-' . $n, $user[$this->options['primary']], time() + 60 * 60 * 24 * 90, PATH);
			setcookie('password-' . $n, password_hash($user[$this->options['password']], PASSWORD_DEFAULT), time() + 60 * 60 * 24 * 90, PATH);
		}
		return $user[$this->options['primary']];
	}

	/**
	 * @return bool
	 */
	public function logout(): bool
	{
		$n = $this->module_id;
		if (isset($_SESSION[SESSION_ID]['user-' . $n]))
			unset($_SESSION[SESSION_ID]['user-' . $n]);
		if (!$this->model->isCLI() and (isset($_COOKIE['user-' . $n]) or isset($_COOKIE['password-' . $n]))) {
			setcookie('user-' . $n, '', 0, PATH);
			setcookie('password-' . $n, '', 0, PATH);
			unset($_COOKIE['user-' . $n]);
			unset($_COOKIE['password-' . $n]);
		}
		return true;
	}

	/**
	 * @return bool|int
	 */
	public function logged()
	{
		$n = $this->module_id;
		return isset($_SESSION[SESSION_ID]['user-' . $n]) ? $_SESSION[SESSION_ID]['user-' . $n][$this->options['primary']] : false;
	}

	/**
	 * @return bool|int
	 */
	private function cookieLogin()
	{
		if ($this->options['table'] === false)
			return false;
		$n = $this->module_id;

		if (!isset($_SESSION[SESSION_ID]['user-' . $n]) and isset($_COOKIE['user-' . $n], $_COOKIE['password-' . $n])) {
			$where = array_merge($this->options['filters'], [
				$this->options['primary'] => $_COOKIE['user-' . $n],
			]);
			$user = $this->model->_Db->select($this->options['table'], $where);
			if ($user and password_verify($user[$this->options['password']], $_COOKIE['password-' . $n])) {
				return $this->directLogin($user, true);
			} else {
				$this->logout();
			}
		}

		return false;
	}

	/**
	 * @return bool
	 */
	public function reload(): bool
	{
		if ($this->options['table'] === false)
			return false;
		$n = $this->module_id;

		if (isset($_SESSION[SESSION_ID]['user-' . $n])) {
			$_SESSION[SESSION_ID]['user-' . $n] = $this->model->_Db->select($this->options['table'], [
				$this->options['primary'] => $_SESSION[SESSION_ID]['user-' . $n][$this->options['primary']],
			]);
		}

		return true;
	}

	/**
	 * @param string $i
	 * @return mixed
	 */
	public function __get($i)
	{
		return $this->get($i);
	}

	/**
	 * @param string|null $i
	 * @return mixed
	 */
	public function get(string $i = null)
	{
		$n = $this->module_id;
		if ($i === null)
			return $_SESSION[SESSION_ID]['user-' . $n];
		elseif (isset($_SESSION[SESSION_ID]['user-' . $n][$i]))
			return $_SESSION[SESSION_ID]['user-' . $n][$i];
		else
			return null;
	}

	/**
	 * @param string $controllerName
	 * @throws \Exception
	 */
	private function checkMandatory(string $controllerName)
	{
		if ($this->logged())
			return;

		$except = $this->options['except'];
		$except[] = $this->options['login-controller'];
		$except[] = 'Zk';

		$controllerName = explode('\\', $controllerName);
		$controllerName = end($controllerName);

		if ($this->options['mandatory'] and !in_array($controllerName, $except) and in_array($this->model->leadingModule, $this->options['affected-modules'])) {
			$redirect = $this->model->prefix() . implode('/', $this->model->getRequest());
			if (!$this->model->isCLI())
				$redirect = urlencode($redirect);
			$this->model->redirect($this->model->getUrl($this->options['login-controller']) . '?redirect=' . $redirect);
		}
	}

	/**
	 * Returns hashed password based on the chosen algorithm
	 *
	 * @param string $password
	 * @return string
	 */
	public function crypt(string $password): string
	{
		switch ($this->options['algorithm-version']) {
			case 'old':
				return $this->options['old-crypt-function']($password);
				break;
			case 'new':
				return $this->options['crypt-function']($password);
				break;
			default:
				$this->model->error('Unrecognized algorithm');
				break;
		}
	}
}
