from neo4j import GraphDatabase
import json
import os
from typing import Dict, List, Optional, Any

class QuestionnaireNeo4j:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="password"):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.questionnaire_path = "c:\\Users\\allie\\Coding Projects\\huginn\\resources\\mindmap"
        
    def close(self):
        self.driver.close()
    
    def load_questionnaires(self):
        """Load all questionnaire files and create graph structure"""
        questionnaires = {}
        
        # Load opening questionnaire
        with open(os.path.join(self.questionnaire_path, "opening_questionnaire.json"), 'r') as f:
            questionnaires['opening'] = json.load(f)
        
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
        """Create Neo4j graph from questionnaires"""
        questionnaires = self.load_questionnaires()
        
        with self.driver.session() as session:
            # Clear existing data
            session.run("MATCH (n) DETACH DELETE n")
            
            # Create opening question
            opening = questionnaires['opening']
            session.run("""
                CREATE (q:Question {
                    id: $id,
                    text: $text,
                    type: $type,
                    options: $options
                })
            """, id=opening['id'], text=opening['text'], 
                type=opening['type'], options=opening['options'])
            
            # Create questionnaire nodes for each environment
            for env_type in ['standalone', 'ad', 'aws', 'azure', 'gcp']:
                if env_type in questionnaires:
                    self._create_questionnaire_nodes(session, env_type, questionnaires[env_type])
            
            # Create relationships from opening to questionnaires
            for option, next_q in opening['next'].items():
                env_key = self._get_env_key(next_q)
                if env_key:
                    session.run("""
                        MATCH (opening:Question {id: $opening_id})
                        MATCH (env:Category {environment: $env})
                        CREATE (opening)-[:LEADS_TO {option: $option}]->(env)
                    """, opening_id=opening['id'], env=env_key, option=option)
    
    def _get_env_key(self, questionnaire_name: str) -> Optional[str]:
        """Map questionnaire names to environment keys"""
        mapping = {
            "standalone_server_questionnaire": "standalone",
            "ad_pen_test_questionnaire_detailed": "ad",
            "aws_pen_test_questionnaire_detailed": "aws", 
            "azure_pen_test_questionnaire_detailed": "azure",
            "gcp_pen_test_questionnaire_detailed": "gcp"
        }
        return mapping.get(questionnaire_name)
    
    def _create_questionnaire_nodes(self, session, env_type: str, questionnaire: Dict):
        """Create nodes for a specific questionnaire"""
        for category, questions in questionnaire.items():
            # Create category node
            session.run("""
                CREATE (c:Category {
                    name: $category,
                    environment: $env_type
                })
            """, category=category, env_type=env_type)
            
            # Create question nodes and relationships
            for i, question in enumerate(questions):
                session.run("""
                    CREATE (q:Question {
                        id: $id,
                        text: $text,
                        type: $type,
                        options: $options,
                        category: $category,
                        environment: $env_type,
                        order: $order
                    })
                """, id=question['id'], text=question['text'],
                    type=question['type'], 
                    options=question.get('options', []),
                    category=category, env_type=env_type, order=i)
                
                # Link question to category
                session.run("""
                    MATCH (c:Category {name: $category, environment: $env_type})
                    MATCH (q:Question {id: $id})
                    CREATE (c)-[:CONTAINS]->(q)
                """, category=category, env_type=env_type, id=question['id'])
    
    def get_opening_question(self) -> Dict:
        """Get the opening question"""
        with self.driver.session() as session:
            result = session.run("""
                MATCH (q:Question {id: 'env_select'})
                RETURN q.text as text, q.options as options
            """)
            record = result.single()
            return {
                'text': record['text'],
                'options': record['options']
            } if record else {}
    
    def get_questionnaire_by_environment(self, environment: str) -> Dict:
        """Get all questions for a specific environment"""
        with self.driver.session() as session:
            result = session.run("""
                MATCH (c:Category {environment: $env})-[:CONTAINS]->(q:Question)
                RETURN c.name as category, 
                       collect({
                           id: q.id,
                           text: q.text,
                           type: q.type,
                           options: q.options,
                           order: q.order
                       }) as questions
                ORDER BY c.name
            """, env=environment)
            
            questionnaire = {}
            for record in result:
                # Sort questions by order
                questions = sorted(record['questions'], key=lambda x: x['order'])
                questionnaire[record['category']] = questions
            
            return questionnaire
    
    def save_response(self, session_id: str, question_id: str, response: Any):
        """Save user response to a question"""
        with self.driver.session() as session:
            session.run("""
                MERGE (s:Session {id: $session_id})
                MERGE (r:Response {session_id: $session_id, question_id: $question_id})
                SET r.answer = $response, r.timestamp = datetime()
                MERGE (s)-[:HAS_RESPONSE]->(r)
            """, session_id=session_id, question_id=question_id, response=response)
    
    def get_session_responses(self, session_id: str) -> Dict:
        """Get all responses for a session"""
        with self.driver.session() as session:
            result = session.run("""
                MATCH (s:Session {id: $session_id})-[:HAS_RESPONSE]->(r:Response)
                RETURN r.question_id as question_id, r.answer as answer
            """, session_id=session_id)
            
            return {record['question_id']: record['answer'] for record in result}