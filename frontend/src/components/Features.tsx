import { useEffect, useRef, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Mic, Brain, Zap, Shield, Clock, Users } from "lucide-react";

const features = [
  {
    icon: Mic,
    title: "Smart Meeting Transcription",
    description: "Advanced AI automatically captures and transcribes your meetings with 99% accuracy, identifying speakers and key discussion points.",
  },
  {
    icon: Brain,
    title: "Intelligent Task Extraction",
    description: "AI analyzes conversations to identify actionable items, deadlines, and responsibilities without manual input.",
  },
  {
    icon: Zap,
    title: "Instant Jira & Trello Integration",
    description: "Automatically creates tickets in your existing workflow tools with proper labels, priorities, and assignments.",
  },
  {
    icon: Shield,
    title: "Enterprise-Grade Security",
    description: "Bank-level encryption ensures your sensitive meeting data stays protected and compliant with industry standards.",
  },
  {
    icon: Clock,
    title: "Real-Time Processing",
    description: "Get your action items ready before the meeting ends. No waiting, no delays, just instant productivity.",
  },
  {
    icon: Users,
    title: "Team Collaboration",
    description: "Seamlessly share insights across teams with smart notifications and automated status updates.",
  },
];

const Features = () => {
  const [visibleCards, setVisibleCards] = useState<number[]>([]);
  const sectionRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const cardIndex = parseInt(entry.target.getAttribute('data-index') || '0');
            setVisibleCards(prev => [...prev, cardIndex]);
          }
        });
      },
      { threshold: 0.2 }
    );

    const cards = sectionRef.current?.querySelectorAll('.feature-card');
    cards?.forEach(card => observer.observe(card));

    return () => observer.disconnect();
  }, []);

  return (
    <section id="features" ref={sectionRef} className="py-20 px-6">
      <div className="container mx-auto">
        <div className="text-center space-y-6 mb-16">
          <h2 className="text-4xl md:text-5xl font-bold">
            Powerful <span className="text-primary glow-text">AI Features</span>
          </h2>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Experience the future of meeting productivity with our cutting-edge AI technology
          </p>
        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
          {features.map((feature, index) => {
            const Icon = feature.icon;
            const isVisible = visibleCards.includes(index);
            
            return (
              <Card
                key={index}
                data-index={index}
                className={`feature-card h-full transition-all duration-700 ${
                  isVisible 
                    ? 'opacity-100 translate-y-0' 
                    : 'opacity-0 translate-y-8'
                }`}
                style={{ 
                  transitionDelay: `${index * 100}ms`
                }}
              >
                <CardHeader className="space-y-4">
                  <div className="w-12 h-12 bg-primary/10 rounded-xl flex items-center justify-center">
                    <Icon className="w-6 h-6 text-primary" />
                  </div>
                  <CardTitle className="text-xl">{feature.title}</CardTitle>
                </CardHeader>
                <CardContent>
                  <CardDescription className="text-muted-foreground leading-relaxed">
                    {feature.description}
                  </CardDescription>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </div>
    </section>
  );
};

export default Features;