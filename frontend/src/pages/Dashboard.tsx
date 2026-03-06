import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Plus, ExternalLink, Calendar, Users, CheckCircle } from "lucide-react";

const Dashboard = () => {
  const [projectUrl, setProjectUrl] = useState("");
  
  // Mock data for existing projects
  const projects = [
    {
      id: 1,
      name: "Mobile App Redesign",
      lastUpdate: "2 hours ago",
      tasksCompleted: 12,
      totalTasks: 18,
      team: 4,
      status: "In Progress"
    },
    {
      id: 2,
      name: "API Integration",
      lastUpdate: "1 day ago",
      tasksCompleted: 8,
      totalTasks: 8,
      team: 2,
      status: "Completed"
    },
    {
      id: 3,
      name: "User Dashboard",
      lastUpdate: "3 days ago",
      tasksCompleted: 15,
      totalTasks: 22,
      team: 6,
      status: "In Progress"
    }
  ];

  const handleAddProject = (e: React.FormEvent) => {
    e.preventDefault();
    // Handle project addition logic here
    console.log("Adding project:", projectUrl);
    setProjectUrl("");
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-background/80">
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-primary/10 via-background to-background"></div>
      
      <div className="relative z-10 container mx-auto px-4 py-8">
        <div className="mb-8">
          <h1 className="text-4xl font-bold bg-gradient-to-r from-primary to-primary-glow bg-clip-text text-transparent mb-2">
            Dashboard
          </h1>
          <p className="text-muted-foreground">
            Manage your projects and track AI automation progress
          </p>
        </div>

        {/* Add Project Section */}
        <Card className="mb-8 border-primary/20 shadow-xl backdrop-blur-sm">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Plus className="h-5 w-5 text-primary" />
              Add New Project
            </CardTitle>
            <CardDescription>
              Paste your Jira or Trello project link to start AI automation
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleAddProject} className="flex gap-4">
              <div className="flex-1">
                <Label htmlFor="projectUrl" className="sr-only">Project URL</Label>
                <Input
                  id="projectUrl"
                  type="url"
                  placeholder="https://your-domain.atlassian.net/jira/software/projects/..."
                  value={projectUrl}
                  onChange={(e) => setProjectUrl(e.target.value)}
                  required
                  className="bg-background/50 border-border/50 focus:border-primary/50 transition-all duration-300"
                />
              </div>
              <Button 
                type="submit"
                className="bg-gradient-to-r from-primary to-primary-glow hover:shadow-glow transition-all duration-300 hover:scale-[1.02] whitespace-nowrap"
              >
                Add Project
              </Button>
            </form>
          </CardContent>
        </Card>

        {/* Projects Grid */}
        <div className="space-y-4">
          <h2 className="text-2xl font-semibold text-foreground">Recent Projects</h2>
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {projects.map((project) => (
              <Card 
                key={project.id} 
                className="border-primary/20 shadow-xl backdrop-blur-sm hover:shadow-2xl hover:border-primary/40 transition-all duration-300 hover:scale-[1.02] cursor-pointer group"
              >
                <CardHeader className="pb-3">
                  <div className="flex items-start justify-between">
                    <CardTitle className="text-lg group-hover:text-primary transition-colors">
                      {project.name}
                    </CardTitle>
                    <ExternalLink className="h-4 w-4 text-muted-foreground group-hover:text-primary transition-colors" />
                  </div>
                  <CardDescription className="flex items-center gap-1">
                    <Calendar className="h-3 w-3" />
                    {project.lastUpdate}
                  </CardDescription>
                </CardHeader>
                
                <CardContent className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <CheckCircle className="h-4 w-4 text-primary" />
                      <span className="text-sm">
                        {project.tasksCompleted}/{project.totalTasks} tasks
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Users className="h-4 w-4 text-muted-foreground" />
                      <span className="text-sm text-muted-foreground">{project.team}</span>
                    </div>
                  </div>
                  
                  <div className="w-full bg-secondary rounded-full h-2">
                    <div 
                      className="bg-gradient-to-r from-primary to-primary-glow h-2 rounded-full transition-all duration-300"
                      style={{ width: `${(project.tasksCompleted / project.totalTasks) * 100}%` }}
                    ></div>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span 
                      className={`px-2 py-1 rounded-full text-xs font-medium ${
                        project.status === 'Completed' 
                          ? 'bg-green-500/20 text-green-400' 
                          : 'bg-primary/20 text-primary'
                      }`}
                    >
                      {project.status}
                    </span>
                    <span className="text-sm text-muted-foreground">
                      {Math.round((project.tasksCompleted / project.totalTasks) * 100)}% complete
                    </span>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;