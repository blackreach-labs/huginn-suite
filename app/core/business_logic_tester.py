import asyncio

class BusinessLogicTester:
    """Test for business logic vulnerabilities"""
    
    def __init__(self):
        self.logic_tests = [
            'price_manipulation',
            'quantity_bypass',
            'workflow_bypass',
            'privilege_escalation',
            'race_conditions'
        ]
    
    async def test_business_logic(self, session, parameters):
        """Test for business logic vulnerabilities"""
        findings = []
        
        for url, forms in parameters.items():
            for form in forms:
                # Test different business logic scenarios
                logic_findings = await self._test_form_logic(session, form)
                findings.extend(logic_findings)
        
        return findings
    
    async def _test_form_logic(self, session, form):
        """Test business logic on individual form"""
        findings = []
        
        # Test price manipulation
        price_findings = await self._test_price_manipulation(session, form)
        findings.extend(price_findings)
        
        # Test quantity bypass
        quantity_findings = await self._test_quantity_bypass(session, form)
        findings.extend(quantity_findings)
        
        # Test negative values
        negative_findings = await self._test_negative_values(session, form)
        findings.extend(negative_findings)
        
        # Test workflow bypass
        workflow_findings = await self._test_workflow_bypass(session, form)
        findings.extend(workflow_findings)
        
        return findings
    
    async def _test_price_manipulation(self, session, form):
        """Test for price manipulation vulnerabilities"""
        findings = []
        
        # Find price-related fields
        price_fields = [f for f in form['inputs'] if self._is_price_field(f['name'])]
        
        for field in price_fields:
            test_values = ['0', '-1', '0.01', '999999999']
            
            for value in test_values:
                try:
                    data = {field['name']: value}
                    # Add other required fields with default values
                    for other_field in form['inputs']:
                        if other_field['name'] != field['name']:
                            data[other_field['name']] = 'test'
                    
                    if form['method'].lower() == 'post':
                        async with session.post(form['action'], data=data) as response:
                            content = await response.text()
                            
                            # Check for successful processing of manipulated price
                            if self._indicates_success(content, response.status):
                                findings.append({
                                    'type': 'Price Manipulation',
                                    'severity': 'HIGH',
                                    'url': form['action'],
                                    'parameter': field['name'],
                                    'test_value': value,
                                    'description': f'Price field accepts invalid value: {value}',
                                    'recommendation': 'Implement server-side price validation and integrity checks'
                                })
                                break  # Stop on first successful manipulation
                    
                    await asyncio.sleep(0.2)
                    
                except Exception:
                    continue
        
        return findings
    
    async def _test_quantity_bypass(self, session, form):
        """Test for quantity bypass vulnerabilities"""
        findings = []
        
        # Find quantity-related fields
        quantity_fields = [f for f in form['inputs'] if self._is_quantity_field(f['name'])]
        
        for field in quantity_fields:
            test_values = ['0', '-1', '999999999', '1.5']
            
            for value in test_values:
                try:
                    data = {field['name']: value}
                    # Add other required fields
                    for other_field in form['inputs']:
                        if other_field['name'] != field['name']:
                            data[other_field['name']] = 'test'
                    
                    if form['method'].lower() == 'post':
                        async with session.post(form['action'], data=data) as response:
                            content = await response.text()
                            
                            if self._indicates_success(content, response.status):
                                findings.append({
                                    'type': 'Quantity Bypass',
                                    'severity': 'MEDIUM',
                                    'url': form['action'],
                                    'parameter': field['name'],
                                    'test_value': value,
                                    'description': f'Quantity field accepts invalid value: {value}',
                                    'recommendation': 'Implement proper quantity validation and limits'
                                })
                                break
                    
                    await asyncio.sleep(0.2)
                    
                except Exception:
                    continue
        
        return findings
    
    async def _test_negative_values(self, session, form):
        """Test for negative value acceptance"""
        findings = []
        
        # Find numeric fields
        numeric_fields = [f for f in form['inputs'] if 
                         f['type'] in ['number', 'text'] and 
                         any(keyword in f['name'].lower() for keyword in 
                             ['amount', 'total', 'sum', 'balance', 'credit'])]
        
        for field in numeric_fields:
            try:
                data = {field['name']: '-999'}
                # Add other required fields
                for other_field in form['inputs']:
                    if other_field['name'] != field['name']:
                        data[other_field['name']] = 'test'
                
                if form['method'].lower() == 'post':
                    async with session.post(form['action'], data=data) as response:
                        content = await response.text()
                        
                        if self._indicates_success(content, response.status):
                            findings.append({
                                'type': 'Negative Value Acceptance',
                                'severity': 'MEDIUM',
                                'url': form['action'],
                                'parameter': field['name'],
                                'description': f'Field accepts negative values: {field["name"]}',
                                'recommendation': 'Implement validation to prevent negative values where inappropriate'
                            })
                
                await asyncio.sleep(0.2)
                
            except Exception:
                continue
        
        return findings
    
    async def _test_workflow_bypass(self, session, form):
        """Test for workflow bypass vulnerabilities"""
        findings = []
        
        # Look for status or state fields
        state_fields = [f for f in form['inputs'] if self._is_state_field(f['name'])]
        
        for field in state_fields:
            # Try to set advanced states
            advanced_states = ['approved', 'completed', 'admin', 'confirmed', 'verified']
            
            for state in advanced_states:
                try:
                    data = {field['name']: state}
                    # Add other required fields
                    for other_field in form['inputs']:
                        if other_field['name'] != field['name']:
                            data[other_field['name']] = 'test'
                    
                    if form['method'].lower() == 'post':
                        async with session.post(form['action'], data=data) as response:
                            content = await response.text()
                            
                            if self._indicates_success(content, response.status):
                                findings.append({
                                    'type': 'Workflow Bypass',
                                    'severity': 'HIGH',
                                    'url': form['action'],
                                    'parameter': field['name'],
                                    'bypassed_state': state,
                                    'description': f'Workflow can be bypassed by setting state to: {state}',
                                    'recommendation': 'Implement proper workflow validation and state transitions'
                                })
                                break
                    
                    await asyncio.sleep(0.2)
                    
                except Exception:
                    continue
        
        return findings
    
    def _is_price_field(self, field_name):
        """Check if field is price-related"""
        price_indicators = ['price', 'cost', 'amount', 'total', 'subtotal', 'fee', 'charge']
        return any(indicator in field_name.lower() for indicator in price_indicators)
    
    def _is_quantity_field(self, field_name):
        """Check if field is quantity-related"""
        quantity_indicators = ['quantity', 'qty', 'count', 'number', 'items']
        return any(indicator in field_name.lower() for indicator in quantity_indicators)
    
    def _is_state_field(self, field_name):
        """Check if field is state/status-related"""
        state_indicators = ['status', 'state', 'stage', 'step', 'phase', 'level', 'role']
        return any(indicator in field_name.lower() for indicator in state_indicators)
    
    def _indicates_success(self, content, status_code):
        """Check if response indicates successful processing"""
        if status_code in [200, 201, 302]:
            success_indicators = ['success', 'complete', 'confirmed', 'approved', 'thank you']
            content_lower = content.lower()
            return any(indicator in content_lower for indicator in success_indicators)
        return False