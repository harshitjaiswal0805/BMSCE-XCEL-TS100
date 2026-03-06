const Footer = () => {
  return (
    <footer className="bg-secondary/30 border-t border-border py-12 px-6">
      <div className="container mx-auto">
        <div className="grid md:grid-cols-4 gap-8 mb-8">
          <div className="space-y-4">
            <div className="flex items-center space-x-2">
              <div className="w-6 h-6 bg-primary rounded-lg flex items-center justify-center">
                <span className="text-primary-foreground font-bold text-xs">C</span>
              </div>
              <span className="text-xl font-bold">curia.AI</span>
            </div>
            <p className="text-sm text-muted-foreground">
              Transforming meetings into actionable results with AI-powered automation.
            </p>
          </div>
          
          <div>
            <h3 className="font-semibold mb-3">Product</h3>
            <div className="space-y-2 text-sm">
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors block">Features</a>
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors block">Pricing</a>
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors block">Integrations</a>
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors block">API</a>
            </div>
          </div>
          
          <div>
            <h3 className="font-semibold mb-3">Company</h3>
            <div className="space-y-2 text-sm">
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors block">About</a>
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors block">Blog</a>
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors block">Careers</a>
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors block">Contact</a>
            </div>
          </div>
          
          <div>
            <h3 className="font-semibold mb-3">Support</h3>
            <div className="space-y-2 text-sm">
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors block">Documentation</a>
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors block">Help Center</a>
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors block">Community</a>
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors block">Status</a>
            </div>
          </div>
        </div>
        
        <div className="border-t border-border pt-8">
          <div className="flex flex-col md:flex-row justify-between items-center space-y-4 md:space-y-0">
            <p className="text-sm text-muted-foreground">
              © 2024 curia.AI. All rights reserved.
            </p>
            <div className="flex space-x-6 text-sm">
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors">Privacy Policy</a>
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors">Terms of Service</a>
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors">Cookie Policy</a>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;