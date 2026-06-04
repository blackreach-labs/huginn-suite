import networkx as nx
import json
import os
from typing import Dict, List, Optional, Any
import pickle
from app.core.logger import logger

class QuestionnaireGraph:
    def __init__(self):
        self.graph = nx.DiGraph()
        # Resolve paths relative to the project root
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.questionnaire_path = os.path.join(base_dir, "resources", "mindmap")
        self.sessions = {}
        self.db_file = os.path.join(base_dir, "resources", "questionnaire_graph.pkl")
        self.load_graph()
        
    def load_questionnaires(self):
        """Load all questionnaire files"""
        questionnaires = {}
        
        # Load opening questionnaire
        with open(os.path.join(self.questionnaire_path, "opening_questionnaire.json"), 'r') as f:
            questionnaires['opening'] = json.load(f)
        
        # Load environment selection
        with open(os.path.join(self.questionnaire_path, "environment_selection.json"), 'r') as f:
            questionnaires['environment_selection'] = json.load(f)
        
        # Load guided workflow
        guided_path = os.path.join(self.questionnaire_path, "guided_workflow_questionnaire.json")
        if os.path.exists(guided_path):
            with open(guided_path, 'r') as f:
                questionnaires['guided_workflow'] = json.load(f)
        else:
            questionnaires['guided_workflow'] = {}
        
        # Load specific questionnaires
        files = [
            "standalone_pen_test_questionnaire_detailed.json",
            "ad_pen_test_questionnaire_detailed.json", 
            "aws_pen_test_questionnaire_detailed.json",
            "azure_pen_test_questionnaire_detailed.json",
            "gcp_pen_test_questionnaire_detailed.json"
        ]
        
        for file in files:
            key = file.replace("_pen_test_questionnaire_detailed.json", "").replace("_questionnaire_detailed.json", "")
            with open(os.path.join(self.questionnaire_path, file), 'r') as f:
                questionnaires[key] = json.load(f)
        
        return questionnaires
    
    def create_graph(self):
        """Create NetworkX graph from questionnaires"""
        questionnaires = self.load_questionnaires()
        self.graph.clear()
        
        # Create opening question
        opening = questionnaires['opening']
        self.graph.add_node('workflow_select', 
                           text=opening['text'],
                           type=opening['type'],
                           options=opening['options'],
                           node_type='question')
        
        # Create environment selection question
        if 'environment_selection' in questionnaires:
            env_sel = questionnaires['environment_selection']
            self.graph.add_node('env_select',
                               text=env_sel['text'],
                               type=env_sel['type'], 
                               options=env_sel['options'],
                               node_type='question')
        
        # Create questionnaire nodes for guided workflow and environments
        if 'guided_workflow' in questionnaires and questionnaires['guided_workflow']:
            self._create_questionnaire_nodes('guided_workflow', questionnaires['guided_workflow'])
        
        for env_type in ['standalone', 'ad', 'aws', 'azure', 'gcp']:
            if env_type in questionnaires:
                self._create_questionnaire_nodes(env_type, questionnaires[env_type])
        
        # Create workflow selection relationships
        workflow_mapping = {
            'Guided Workflow (Step-by-step)': 'guided_workflow',
            'Environment-Specific (AD/AWS/Azure/GCP)': 'environment_selection'
        }
        
        for option, next_q in workflow_mapping.items():
            if next_q in questionnaires and questionnaires[next_q]:
                self.graph.add_edge('workflow_select', f'{next_q}_root', option=option)
        
        # Create environment selection relationships
        env_mapping = {
            'Standalone Server': 'standalone',
            'Active Directory': 'ad',
            'Microsoft Azure': 'azure', 
            'AWS': 'aws',
            'Google Cloud': 'gcp'
        }
        
        for option, env_key in env_mapping.items():
            if env_key in questionnaires:
                self.graph.add_edge('env_select', f'{env_key}_root', option=option)
        
        self.save_graph()
    
    def _create_questionnaire_nodes(self, env_type: str, questionnaire: Dict):
        """Create nodes for a specific questionnaire"""
        # Create root node for environment
        self.graph.add_node(f'{env_type}_root', 
                           environment=env_type,
                           node_type='environment')
        
        for category, questions in questionnaire.items():
            category_id = f'{env_type}_{category.lower().replace(" ", "_")}'
            
            # Create category node
            self.graph.add_node(category_id,
                               name=category,
                               environment=env_type,
                               node_type='category')
            
            # Link environment to category
            self.graph.add_edge(f'{env_type}_root', category_id)
            
            # Create question nodes
            for i, question in enumerate(questions):
                question_id = question['id']
                self.graph.add_node(question_id,
                                   text=question['text'],
                                   type=question['type'],
                                   options=question.get('options', []),
                                   placeholder=question.get('placeholder', ''),
                                   action=question.get('action', ''),
                                   category=category,
                                   environment=env_type,
                                   order=i,
                                   node_type='question')
                
                # Link category to question
                self.graph.add_edge(category_id, question_id)
    
    def get_opening_question(self) -> Dict:
        """Get the opening question"""
        if 'workflow_select' in self.graph:
            node = self.graph.nodes['workflow_select']
            return {
                'text': node['text'],
                'options': node['options']
            }
        return {}
    
    def get_questionnaire_by_environment(self, environment: str) -> Dict:
        """Get all questions for a specific environment"""
        questionnaire = {}
        
        # Find all categories for this environment
        for node_id, data in self.graph.nodes(data=True):
            if (data.get('node_type') == 'category' and 
                data.get('environment') == environment):
                
                category_name = data['name']
                questions = []
                
                # Get questions for this category
                for successor in self.graph.successors(node_id):
                    question_data = self.graph.nodes[successor]
                    if question_data.get('node_type') == 'question':
                        questions.append({
                            'id': successor,
                            'text': question_data['text'],
                            'type': question_data['type'],
                            'options': question_data['options'],
                            'placeholder': question_data.get('placeholder', ''),
                            'action': question_data.get('action', ''),
                            'order': question_data['order']
                        })
                
                # Sort by order
                questions.sort(key=lambda x: x['order'])
                questionnaire[category_name] = questions
        
        return questionnaire
    
    def save_response(self, session_id: str, question_id: str, response: Any):
        """Save user response"""
        if session_id not in self.sessions:
            self.sessions[session_id] = {}
        
        import datetime
        self.sessions[session_id][question_id] = {
            'answer': response,
            'timestamp': str(datetime.datetime.now())
        }
        self.save_graph()
    
    def get_session_responses(self, session_id: str) -> Dict:
        """Get all responses for a session"""
        if session_id in self.sessions:
            return {qid: data['answer'] for qid, data in self.sessions[session_id].items()}
        return {}
    
    def save_graph(self):
        """Save graph to file"""
        try:
            data = {
                'graph': self.graph,
                'sessions': self.sessions
            }
            with open(self.db_file, 'wb') as f:
                pickle.dump(data, f)
        except Exception as _exc:
            pass  # Fail silently
            logger.debug("Suppressed exception", exc_info=True)
    
    def load_graph(self):
        """Load graph from file"""
        try:
            if os.path.exists(self.db_file):
                with open(self.db_file, 'rb') as f:
                    data = pickle.load(f)
                    self.graph = data.get('graph', nx.DiGraph())
                    self.sessions = data.get('sessions', {})
            else:
                self.create_graph()
        except Exception:
            self.create_graph()  # Create new if load fails