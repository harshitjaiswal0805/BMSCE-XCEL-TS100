import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

const Signup = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    password: "",
    confirmPassword: "",
    jiraEmail: "",
    jiraApiToken: "",
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    
    if (formData.password !== formData.confirmPassword) {
      setError("Passwords don't match");
      return;
    }

    setLoading(true);

    try {
      const response = await fetch('http://localhost:5000/api/auth/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: formData.name,
          email: formData.email,
          password: formData.password,
          jiraEmail: formData.jiraEmail,
          jiraApiToken: formData.jiraApiToken,
        }),
      });

      const data = await response.json();

      if (data.success) {
        // Store token and user data
        localStorage.setItem('token', data.user.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        
        // Navigate to dashboard
        navigate("/dashboard");
      } else {
        setError(data.message || 'Registration failed');
      }
    } catch (err) {
      setError('Network error. Please try again.');
      console.error('Registration error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData(prev => ({
      ...prev,
      [e.target.name]: e.target.value
    }));
    // Clear error when user starts typing
    if (error) setError("");
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-background/80 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-primary/20 via-background to-background"></div>
      
      <Card className="w-full max-w-md relative backdrop-blur-sm border-primary/20 shadow-2xl animate-fade-in">
        <CardHeader className="text-center space-y-4">
          <div className="mx-auto w-16 h-16 rounded-full bg-gradient-to-r from-primary to-primary-glow flex items-center justify-center shadow-glow">
            <span className="text-2xl font-bold text-primary-foreground">C</span>
          </div>
          <CardTitle className="text-2xl font-bold bg-gradient-to-r from-primary to-primary-glow bg-clip-text text-transparent">
            Join curia.AI
          </CardTitle>
          <CardDescription className="text-muted-foreground">
            Create your account and automate your workflow
          </CardDescription>
        </CardHeader>
        
        <CardContent className="space-y-6">
          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <div className="p-3 rounded-md bg-destructive/15 border border-destructive/50 text-destructive text-sm">
                {error}
              </div>
            )}
            
            <div className="space-y-2">
              <Label htmlFor="name">Full Name</Label>
              <Input
                id="name"
                name="name"
                type="text"
                placeholder="Enter your full name"
                value={formData.name}
                onChange={handleChange}
                required
                className="bg-background/50 border-border/50 focus:border-primary/50 transition-all duration-300"
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                name="email"
                type="email"
                placeholder="Enter your email"
                value={formData.email}
                onChange={handleChange}
                required
                className="bg-background/50 border-border/50 focus:border-primary/50 transition-all duration-300"
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                name="password"
                type="password"
                placeholder="Create a password (min 6 characters)"
                value={formData.password}
                onChange={handleChange}
                required
                minLength={6}
                className="bg-background/50 border-border/50 focus:border-primary/50 transition-all duration-300"
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="confirmPassword">Confirm Password</Label>
              <Input
                id="confirmPassword"
                name="confirmPassword"
                type="password"
                placeholder="Confirm your password"
                value={formData.confirmPassword}
                onChange={handleChange}
                required
                className="bg-background/50 border-border/50 focus:border-primary/50 transition-all duration-300"
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="jiraEmail">Jira Email</Label>
              <Input
                id="jiraEmail"
                name="jiraEmail"
                type="email"
                placeholder="Enter your Jira email"
                value={formData.jiraEmail}
                onChange={handleChange}
                required
                className="bg-background/50 border-border/50 focus:border-primary/50 transition-all duration-300"
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="jiraApiToken">Jira API Token</Label>
              <Input
                id="jiraApiToken"
                name="jiraApiToken"
                type="password"
                placeholder="Enter your Jira API token"
                value={formData.jiraApiToken}
                onChange={handleChange}
                required
                className="bg-background/50 border-border/50 focus:border-primary/50 transition-all duration-300"
              />
              <p className="text-xs text-muted-foreground">
                Get your API token from Jira settings
              </p>
            </div>
            
            <Button 
              type="submit" 
              disabled={loading}
              className="w-full bg-gradient-to-r from-primary to-primary-glow hover:shadow-glow transition-all duration-300 hover:scale-[1.02] disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
            >
              {loading ? "Creating Account..." : "Create Account"}
            </Button>
          </form>
          
          <div className="text-center text-sm text-muted-foreground">
            Already have an account?{" "}
            <Link 
              to="/login" 
              className="text-primary hover:text-primary-glow transition-colors duration-300 font-medium"
            >
              Sign in
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
export default Signup;