# crews/security_crew/security_crew.py
from crewai import Agent, Crew, Process, Task, LLM
from crewai.project import CrewBase, agent, crew, task
from tools.custom_tool import SOCCommunicationTool

@CrewBase
class SecurityCrew():
    """Security monitoring crew for URL threat analysis"""
    
    agents_config = 'config/agents.yaml'
    tasks_config = 'config/tasks.yaml'

    ollama_llm = LLM(
        model="ollama/mistral:7b-instruct-q6_K",
        num_ctx=4096,
    )
    
    @agent
    def url_analyzer_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['url_analyzer_agent'],
            verbose=True,
            allow_delegation=False,
            llm=self.ollama_llm,
            step_callback=lambda step: print(f"Agent step: {step.action}") if hasattr(step, 'action') else None,
        )
    
    @agent  
    def soc_communication_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['soc_communication_agent'],
            verbose=True,
            tools=[SOCCommunicationTool()],
            allow_delegation=False,
            llm=self.ollama_llm,
        )
    
    
    @task
    def url_analysis_task(self) -> Task:
        return Task(
            config=self.tasks_config['url_analysis_task'],
            agent=self.url_analyzer_agent()
        )
    
    @task
    def soc_communication_task(self) -> Task:
        return Task(
            config=self.tasks_config['soc_communication_task'], 
            agent=self.soc_communication_agent(),
            context=[self.url_analysis_task()]  # ✅ Use context instead of template variables
        )
    
    @crew
    def crew(self) -> Crew:
        """Creates the security monitoring crew"""
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,  # ✅ Sequential ensures proper order
            verbose=True
        )
