import { useState } from "react";
import { Button } from "@/components/ui/button";

// Hamburger Icon Component
const MenuIcon = (props) => (
  <svg
    {...props}
    xmlns="http://www.w3.org/2000/svg"
    width="24"
    height="24"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <line x1="4" x2="20" y1="12" y2="12" />
    <line x1="4" x2="20" y1="6" y2="6" />
    <line x1="4" x2="20" y1="18" y2="18" />
  </svg>
);

// Close (X) Icon Component
const XIcon = (props) => (
  <svg
    {...props}
    xmlns="http://www.w3.org/2000/svg"
    width="24"
    height="24"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <path d="M18 6 6 18" />
    <path d="m6 6 12 12" />
  </svg>
);


const Header = () => {
  // State to manage whether the mobile menu is open or closed
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  return (
    <header className="fixed top-0 left-0 right-0 z-50 bg-background/80 backdrop-blur-md border-b border-border">
      <nav className="container mx-auto px-6 py-4">
        <div className="flex items-center justify-between">
          {/* Logo and Brand Name */}
          <div className="flex items-center space-x-2">
            <div className="w-8 h-8 bg-primary rounded-lg flex items-center justify-center animate-glow-pulse">
              <span className="text-primary-foreground font-bold text-sm">C</span>
            </div>
            <span className="text-2xl font-bold glow-text">curia.AI</span>
          </div>

          {/* Desktop Navigation Links */}
          <div className="hidden md:flex items-center space-x-8">
            <a href="#features" className="text-muted-foreground hover:text-primary transition-colors">Features</a>
            <a href="#about" className="text-muted-foreground hover:text-primary transition-colors">About</a>
            <a href="#pricing" className="text-muted-foreground hover:text-primary transition-colors">Pricing</a>
            <div className="flex items-center space-x-4">
              <Button
                variant="ghost"
                className="bg-gradient-primary hover:shadow-glow transition-all duration-300"
                onClick={() => window.location.href = '/login'}
              >
                Sign In
              </Button>
              <Button
                variant="outline"
                className="bg-gradient-primary hover:shadow-glow transition-all duration-300"
                onClick={() => window.location.href = '/signup'}
              >
                Get Started
              </Button>
            </div>
          </div>

          {/* Mobile Menu Button (Hamburger) */}
          <div className="md:hidden flex items-center">
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setIsMenuOpen(!isMenuOpen)}
              aria-label="Toggle menu"
            >
              {isMenuOpen ? <XIcon className="h-6 w-6" /> : <MenuIcon className="h-6 w-6" />}
            </Button>
          </div>
        </div>

        {/* Mobile Menu Dropdown */}
        {isMenuOpen && (
          <div className="md:hidden mt-4 animate-fade-in-down">
            <div className="flex flex-col items-start space-y-4 pt-4 pb-2 border-t border-border">
              <a href="#features" className="text-muted-foreground hover:text-primary transition-colors w-full" onClick={() => setIsMenuOpen(false)}>Features</a>
              <a href="#about" className="text-muted-foreground hover:text-primary transition-colors w-full" onClick={() => setIsMenuOpen(false)}>About</a>
              <a href="#pricing" className="text-muted-foreground hover:text-primary transition-colors w-full" onClick={() => setIsMenuOpen(false)}>Pricing</a>
              <div className="flex flex-col space-y-2 w-full pt-4 border-t border-border">
                 <Button
                    variant="ghost"
                    className="w-full justify-start bg-gradient-primary hover:shadow-glow transition-all duration-300"
                    onClick={() => {
                        window.location.href = '/login';
                        setIsMenuOpen(false);
                    }}
                  >
                    Sign In
                  </Button>
                  <Button
                    variant="outline"
                    className="w-full justify-start bg-gradient-primary hover:shadow-glow transition-all duration-300"
                    onClick={() => {
                        window.location.href = '/signup';
                        setIsMenuOpen(false);
                    }}
                  >
                    Get Started
                  </Button>
              </div>
            </div>
          </div>
        )}
      </nav>
    </header>
  );
};

export default Header;
