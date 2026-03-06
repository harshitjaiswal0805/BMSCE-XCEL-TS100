import React, { useState } from 'react';
import Login from './Login';
import Register from './Register';

const AuthWrapper = () => {
    const [isLoginMode, setIsLoginMode] = useState(true);

    const switchToRegister = () => setIsLoginMode(false);
    const switchToLogin = () => setIsLoginMode(true);

    return (
        <div className="auth-wrapper">
            {isLoginMode ? (
                <Login onSwitchToRegister={switchToRegister} />
            ) : (
                <Register onSwitchToLogin={switchToLogin} />
            )}
        </div>
    );
};

export default AuthWrapper;