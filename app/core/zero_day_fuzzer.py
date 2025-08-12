import random
import hashlib
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class FuzzResult:
    payload: str
    response_code: int
    response_size: int
    response_time: float
    anomaly_score: float

class ZeroDayFuzzer:
    """Evolutionary fuzzing engine for zero-day discovery"""
    
    def __init__(self):
        self.population_size = 50
        self.mutation_rate = 0.3
        self.crossover_rate = 0.7
        self.generations = 10
        self.payload_pool = []
        self.fitness_cache = {}
    
    def initialize_population(self, base_payloads: List[str]) -> List[str]:
        """Initialize fuzzing population with base payloads"""
        population = base_payloads.copy()
        
        # Generate mutations of base payloads
        while len(population) < self.population_size:
            base = random.choice(base_payloads)
            mutated = self._mutate_payload(base)
            if mutated not in population:
                population.append(mutated)
        
        return population[:self.population_size]
    
    def evolve_payloads(self, population: List[str], fitness_scores: List[float]) -> List[str]:
        """Evolve payload population using genetic algorithm"""
        new_population = []
        
        # Keep top performers (elitism)
        elite_count = max(1, self.population_size // 10)
        sorted_pop = sorted(zip(population, fitness_scores), key=lambda x: x[1], reverse=True)
        new_population.extend([p[0] for p in sorted_pop[:elite_count]])
        
        # Generate offspring through crossover and mutation
        while len(new_population) < self.population_size:
            if random.random() < self.crossover_rate:
                parent1, parent2 = self._select_parents(population, fitness_scores)
                offspring = self._crossover(parent1, parent2)
            else:
                parent = self._select_parents(population, fitness_scores)[0]
                offspring = parent
            
            if random.random() < self.mutation_rate:
                offspring = self._mutate_payload(offspring)
            
            new_population.append(offspring)
        
        return new_population[:self.population_size]
    
    def calculate_fitness(self, result: FuzzResult) -> float:
        """Calculate fitness score for fuzzing result"""
        fitness = 0.0
        
        # Reward unusual response codes
        if result.response_code in [500, 502, 503]:
            fitness += 3.0
        elif result.response_code in [400, 403, 404]:
            fitness += 1.0
        elif result.response_code == 200:
            fitness += 0.5
        
        # Reward unusual response sizes
        if result.response_size > 10000 or result.response_size < 100:
            fitness += 2.0
        
        # Reward slow responses (potential DoS)
        if result.response_time > 5.0:
            fitness += 2.0
        elif result.response_time > 2.0:
            fitness += 1.0
        
        # Add anomaly score
        fitness += result.anomaly_score
        
        return fitness
    
    def detect_anomalies(self, results: List[FuzzResult]) -> List[Dict[str, Any]]:
        """Detect anomalous responses that might indicate vulnerabilities"""
        anomalies = []
        
        if not results:
            return anomalies
        
        # Calculate baseline metrics
        avg_size = sum(r.response_size for r in results) / len(results)
        avg_time = sum(r.response_time for r in results) / len(results)
        
        for result in results:
            anomaly_indicators = []
            
            # Size anomalies
            if result.response_size > avg_size * 2:
                anomaly_indicators.append("Large response size")
            elif result.response_size < avg_size * 0.1:
                anomaly_indicators.append("Small response size")
            
            # Time anomalies
            if result.response_time > avg_time * 3:
                anomaly_indicators.append("Slow response time")
            
            # Error codes
            if result.response_code >= 500:
                anomaly_indicators.append("Server error")
            
            if anomaly_indicators:
                anomalies.append({
                    'payload': result.payload,
                    'response_code': result.response_code,
                    'indicators': anomaly_indicators,
                    'severity': self._calculate_anomaly_severity(anomaly_indicators)
                })
        
        return anomalies
    
    def _mutate_payload(self, payload: str) -> str:
        """Apply random mutations to payload"""
        mutations = [
            self._insert_random_chars,
            self._delete_random_chars,
            self._substitute_chars,
            self._duplicate_segments,
            self._insert_special_chars
        ]
        
        mutation_func = random.choice(mutations)
        return mutation_func(payload)
    
    def _insert_random_chars(self, payload: str) -> str:
        """Insert random characters"""
        if not payload:
            return payload
        pos = random.randint(0, len(payload))
        chars = ''.join(random.choices('!@#$%^&*()[]{}|\\:";\'<>?,./`~', k=random.randint(1, 3)))
        return payload[:pos] + chars + payload[pos:]
    
    def _delete_random_chars(self, payload: str) -> str:
        """Delete random characters"""
        if len(payload) <= 2:
            return payload
        start = random.randint(0, len(payload) - 2)
        end = random.randint(start + 1, len(payload))
        return payload[:start] + payload[end:]
    
    def _substitute_chars(self, payload: str) -> str:
        """Substitute random characters"""
        if not payload:
            return payload
        payload_list = list(payload)
        for _ in range(random.randint(1, min(3, len(payload)))):
            pos = random.randint(0, len(payload_list) - 1)
            payload_list[pos] = random.choice('!@#$%^&*()[]{}|\\:";\'<>?,./`~')
        return ''.join(payload_list)
    
    def _duplicate_segments(self, payload: str) -> str:
        """Duplicate random segments"""
        if len(payload) < 4:
            return payload + payload
        start = random.randint(0, len(payload) - 2)
        end = random.randint(start + 1, len(payload))
        segment = payload[start:end]
        return payload + segment
    
    def _insert_special_chars(self, payload: str) -> str:
        """Insert special characters for specific attack types"""
        special_chars = ['%00', '%0a', '%0d', '\\x00', '\\n', '\\r', '../', '..\\\\']
        char = random.choice(special_chars)
        pos = random.randint(0, len(payload))
        return payload[:pos] + char + payload[pos:]
    
    def _select_parents(self, population: List[str], fitness_scores: List[float]) -> List[str]:
        """Select parents using tournament selection"""
        tournament_size = 3
        parents = []
        
        for _ in range(2):
            tournament = random.sample(list(zip(population, fitness_scores)), tournament_size)
            winner = max(tournament, key=lambda x: x[1])
            parents.append(winner[0])
        
        return parents
    
    def _crossover(self, parent1: str, parent2: str) -> str:
        """Create offspring through crossover"""
        if not parent1 or not parent2:
            return parent1 or parent2
        
        # Single-point crossover
        point = random.randint(1, min(len(parent1), len(parent2)) - 1)
        return parent1[:point] + parent2[point:]
    
    def _calculate_anomaly_severity(self, indicators: List[str]) -> str:
        """Calculate severity based on anomaly indicators"""
        if len(indicators) >= 3:
            return "HIGH"
        elif len(indicators) >= 2:
            return "MEDIUM"
        else:
            return "LOW"