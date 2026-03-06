import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { CheckCircle, ArrowRight } from "lucide-react";

const benefits = [
  "Reduce meeting overhead by 70%",
  "Eliminate manual task creation",
  "Improve team accountability",
  "Never miss action items again",
  "Seamless workflow integration",
  "Boost productivity instantly"
];

const About = () => {
  const [isVisible, setIsVisible] = useState(false);
  const sectionRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting) {
          setIsVisible(true);
        }
      },
      { threshold: 0.3 }
    );

    if (sectionRef.current) {
      observer.observe(sectionRef.current);
    }

    return () => observer.disconnect();
  }, []);

  return (
    <section id="about" ref={sectionRef} className="py-20 px-6">
      <div className="container mx-auto">
        <div className="grid lg:grid-cols-2 gap-12 items-center">
          {/* Content */}
          <div className={`space-y-8 transition-all duration-800 ${
            isVisible ? 'opacity-100 translate-x-0' : 'opacity-0 -translate-x-8'
          }`}>
            <div className="space-y-6">
              <h2 className="text-4xl md:text-5xl font-bold leading-tight">
                Transform Every Meeting Into 
                <span className="text-primary glow-text"> Actionable Results</span>
              </h2>
              
              <p className="text-xl text-muted-foreground leading-relaxed">
                curia.AI revolutionizes how teams handle meeting outcomes. Our advanced AI doesn't just listen—it understands context, identifies priorities, and creates perfect project tickets that match your workflow.
              </p>
            </div>

            <div className="space-y-4">
              {benefits.map((benefit, index) => (
                <div 
                  key={index}
                  className={`flex items-center space-x-3 transition-all duration-500 ${
                    isVisible ? 'opacity-100 translate-x-0' : 'opacity-0 translate-x-4'
                  }`}
                  style={{ transitionDelay: `${index * 100 + 200}ms` }}
                >
                  <CheckCircle className="w-5 h-5 text-primary flex-shrink-0" />
                  <span className="text-muted-foreground">{benefit}</span>
                </div>
              ))}
            </div>

            <div className={`transition-all duration-500 ${
              isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'
            }`} style={{ transitionDelay: '800ms' }}>
              <Button 
                size="lg" 
                className="hero-button text-lg px-8 py-6 group"
              >
                Get Started Today
                <ArrowRight className="ml-2 w-5 h-5 group-hover:translate-x-1 transition-transform" />
              </Button>
            </div>
          </div>

          {/* Visual Element */}
          <div className={`relative transition-all duration-800 ${
            isVisible ? 'opacity-100 translate-x-0' : 'opacity-0 translate-x-8'
          }`} style={{ transitionDelay: '400ms' }}>
            <div className="relative bg-gradient-to-br from-primary/10 to-primary/5 rounded-3xl p-8 border border-primary/20">
              <div className="space-y-6">
                <div className="bg-secondary/50 rounded-xl p-4 border border-primary/10">
                  <div className="flex items-center space-x-2 mb-2">
                    <div className="w-2 h-2 bg-primary rounded-full animate-pulse"></div>
                    <span className="text-sm font-medium">Meeting in Progress</span>
                  </div>
                  <p className="text-sm text-muted-foreground">
                    "Let's prioritize the user authentication feature for next sprint..."
                  </p>
                </div>
                
                <div className="bg-secondary/30 rounded-xl p-4 border border-primary/10">
                  <div className="flex items-center space-x-2 mb-2">
                    <CheckCircle className="w-4 h-4 text-primary" />
                    <span className="text-sm font-medium">Auto-Generated Ticket</span>
                  </div>
                  <div className="text-xs space-y-1 text-muted-foreground">
                    <p><strong>Title:</strong> Implement User Authentication</p>
                    <p><strong>Priority:</strong> High</p>
                    <p><strong>Assignee:</strong> Frontend Team</p>
                  </div>
                </div>

                <div className="text-center">
                  <div className="inline-flex items-center space-x-1 text-sm text-primary">
                    <span>Synced to Jira</span>
                    <CheckCircle className="w-4 h-4" />
                  </div>
                </div>
              </div>
              
              {/* Floating elements */}
              <div className="absolute -top-4 -right-4 w-8 h-8 bg-primary/20 rounded-full animate-float"></div>
              <div className="absolute -bottom-2 -left-2 w-6 h-6 bg-primary/30 rounded-full animate-float" style={{ animationDelay: '1s' }}></div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default About;