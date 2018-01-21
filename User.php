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
		if (!is_array($options)) {
			$options = [
				'table' => $options,
			];
		}

		$this->options = array_merge([
			'table' => 'users',
			'primary' => 'id',
			'username' => 'username',
			'password' => 'password',
			'filters' => [],
			'mandatory' => false,
			'except' => [],
			'login-controller' => 'Login',
			'crypt-function' => function ($pass) {
				return sha1(md5($pass));
			},
		], $options);

		$this->methods = [
			'login',
			'directLogin',
			'logout',
			'logged',
		];

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
			$this->options['password'] => $this->options['crypt-function']($password),
		]);
		$user = $this->model->_Db->select($this->options['table'], $where);
		if ($user) {
			return $this->directLogin($user, $remember);
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
			setcookie('password-' . $n, md5($user[$this->options['password']]), time() + 60 * 60 * 24 * 90, PATH);
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
			if ($user and md5($user[$this->options['password']]) == $_COOKIE['password-' . $n]) {
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

		if ($this->options['mandatory'] and !in_array($controllerName, $except)) {
			$redirect = $this->model->prefix() . implode('/', $this->model->getRequest());
			if (!$this->model->isCLI())
				$redirect = urlencode($redirect);
			$this->model->redirect($this->model->getUrl($this->options['login-controller']) . '?redirect=' . $redirect);
		}
	}
}
