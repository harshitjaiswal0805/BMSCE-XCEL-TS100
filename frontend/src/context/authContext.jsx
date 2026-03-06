import React, { createContext, useContext, useReducer, useEffect } from 'react';
import authService from '../services/authService';

const AuthContext = createContext();

const authReducer = (state, action) => {
    switch (action.type) {
        case 'LOGIN_START':
        case 'REGISTER_START':
            return {
                ...state,
                loading: true,
                error: null
            };
        case 'LOGIN_SUCCESS':
        case 'REGISTER_SUCCESS':
            return {
                ...state,
                loading: false,
                user: action.payload,
                isAuthenticated: true,
                error: null
            };
        case 'LOGIN_FAILURE':
        case 'REGISTER_FAILURE':
            return {
                ...state,
                loading: false,
                user: null,
                isAuthenticated: false,
                error: action.payload
            };
        case 'LOGOUT':
            return {
                ...state,
                user: null,
                isAuthenticated: false,
                loading: false,
                error: null
            };
        case 'CLEAR_ERROR':
            return {
                ...state,
                error: null
            };
        default:
            return state;
    }
};

export const AuthProvider = ({ children }) => {
    const [state, dispatch] = useReducer(authReducer, {
        user: null,
        isAuthenticated: false,
        loading: false,
        error: null
    });

    useEffect(() => {
        const user = authService.getCurrentUser();
        const isAuthenticated = authService.isAuthenticated();

        if (user && isAuthenticated) {
            dispatch({ type: 'LOGIN_SUCCESS', payload: user });
        }
    }, []);

    const login = async (credentials) => {
        dispatch({ type: 'LOGIN_START' });
        try {
            const response = await authService.login(credentials);
            if (response.success) {
                dispatch({ type: 'LOGIN_SUCCESS', payload: response.user });
                return { success: true };
            } else {
                dispatch({ type: 'LOGIN_FAILURE', payload: response.message });
                return { success: false, message: response.message };
            }
        } catch (error) {
            dispatch({ type: 'LOGIN_FAILURE', payload: error.message });
            return { success: false, message: error.message };
        }
    };

    const register = async (userData) => {
        dispatch({ type: 'REGISTER_START' });
        try {
            const response = await authService.register(userData);
            if (response.success) {
                dispatch({ type: 'REGISTER_SUCCESS', payload: response.user });
                return { success: true };
            } else {
                dispatch({ type: 'REGISTER_FAILURE', payload: response.message });
                return { success: false, message: response.message };
            }
        } catch (error) {
            dispatch({ type: 'REGISTER_FAILURE', payload: error.message });
            return { success: false, message: error.message };
        }
    };

    const logout = () => {
        authService.logout();
        dispatch({ type: 'LOGOUT' });
    };

    const clearError = () => {
        dispatch({ type: 'CLEAR_ERROR' });
    };

    return (
        <AuthContext.Provider value={{
            ...state,
            login,
            register,
            logout,
            clearError
        }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};
