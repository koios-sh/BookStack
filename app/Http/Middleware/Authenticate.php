<?php

namespace BookStack\Http\Middleware;

use Closure;
use Illuminate\Contracts\Auth\Guard;

class Authenticate
{
    /**
     * The Guard implementation.
     * @var Guard
     */
    protected $auth;

    /**
     * Create a new filter instance.
     * @param  Guard $auth
     */
    public function __construct(Guard $auth)
    {
        $this->auth = $auth;
    }

    function debug_to_console( $data ) {
        $output = $data;
        if ( is_array( $output ) )
            $output = implode( ',', $output);

        echo "<script>console.log( 'Debug Objects: " . $output . "' );</script>";
    }

    /**
     * Handle an incoming request.
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        if ($this->auth->check()) {
            $requireConfirmation = (setting('registration-confirmation') || setting('registration-restrict'));
            if ($requireConfirmation && !$this->auth->user()->email_confirmed) {
                return redirect('/register/confirm/awaiting');
            }
        }
        
        $uri = urldecode(
            parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH)
        );
        // $this->debug_to_console($uri);
        // $this->debug_to_console(substr($uri, 0, 7));

        // 如果访问 /books/${book} 或者 /search，则忽略是否公开访问开关
        if (!((substr($uri, 0, 7) == '/books/' && strlen($uri) > 7) || substr($uri, 0, 8) == '/search/' || substr($uri, 0, 16) == '/uploads/images/') && !hasAppAccess()) {
            if ($request->ajax()) {
                return response('Unauthorized.', 401);
            } else {
                return redirect()->guest(url('/login'));
            }
        }

        return $next($request);
    }
}
