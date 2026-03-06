import { Button } from "@/components/ui/button";
import { ArrowRight, Sparkles } from "lucide-react";

const Hero = () => {
  return (
    <section className="min-h-screen flex items-center justify-center pt-20 px-6">
      <div className="container mx-auto text-center">
        <div className="max-w-4xl mx-auto space-y-8">
          {/* Trust indicator */}
          <div className="animate-fade-in">
            <div className="inline-flex items-center space-x-2 bg-secondary/50 rounded-full px-4 py-2 border border-primary/20">
              <Sparkles className="w-4 h-4 text-primary animate-float" />
              <span className="text-sm text-muted-foreground">
                Trusted by teams at innovative companies
              </span>
            </div>
          </div>

          {/* Main heading */}
          <div className="space-y-6 animate-fade-in" style={{ animationDelay: "0.2s" }}>
            <h1 className="text-5xl md:text-7xl font-bold leading-tight">
              The Future of <span className="text-primary glow-text">AI Meeting</span>
              <br />
              Automation
              <br />
            </h1>
            
            <p className="text-xl text-muted-foreground max-w-2xl mx-auto leading-relaxed">
              Transform your meetings into actionable tasks automatically. 
              curia.AI listens, understands, and creates perfect project tickets without the manual work.
            </p>
          </div>

          {/* CTA Buttons */}
          <div className="flex flex-col sm:flex-row gap-4 justify-center items-center animate-fade-in" style={{ animationDelay: "0.4s" }}>
            <Button 
              size="lg" 
              className="hero-button text-lg px-8 py-6 group"
            >
              Start Free Trial
              <ArrowRight className="ml-2 w-5 h-5 group-hover:translate-x-1 transition-transform" />
            </Button>
            
            <Button 
              variant="outline" 
              size="lg" 
              className="text-lg px-8 py-6 border-primary/30 hover:bg-primary/10"
            >
              Watch Demo
            </Button>
          </div>

          {/* Supporting text */}
          <div className="animate-fade-in" style={{ animationDelay: "0.6s" }}>
            <p className="text-sm text-muted-foreground">
              No credit card required • 14-day free trial • Setup in 2 minutes
            </p>
          </div>
        </div>
      </div>
    </section>
  );
};

export default Hero;