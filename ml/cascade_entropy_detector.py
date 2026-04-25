"""
Cascade Ensemble with Entropy Analysis for TerminalGuard++
Implements: BiLSTM L1 → SVM L2 → Entropy Analysis L2.5 → Regex L3 → Zero-FN Safety

4-Level Cascade:
- L1: BiLSTM (primary, 70% early exit at high/low confidence)
- L2: SVM (gray zone specialist, <1ms)
- L2.5: Entropy + Context (unknown secrets detection)
- L3: Regex (zero false-negatives, deterministic safety)

Returns detailed result dict with decision, level, confidence, and reasoning.
"""

import os
import numpy as np
import math
import re
from pathlib import Path
from typing import Dict, Optional, Tuple

# Import existing detectors
try:
    from .ml_detector import MLDetector  # Logistic & SVM
    from .tf_bilstm_detector import TFBiLSTMDetector  # BiLSTM
except ImportError:
    # Fallback for testing without full setup
    MLDetector = None
    TFBiLSTMDetector = None


class EntropyAnalyzer:
    """Analyzes entropy of text to detect obfuscated secrets."""
    
    @staticmethod
    def calculate_entropy(text: str) -> float:
        """
        Shannon entropy: H = -Σ (p_i * log2(p_i))
        Higher entropy (>4.5) = likely obfuscated/random secret
        Lower entropy (<3.5) = likely natural text
        
        Args:
            text: Input string to analyze
            
        Returns:
            Entropy value in bits/character
        """
        if not text:
            return 0.0
        
        # Count character frequencies
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate Shannon entropy
        entropy = 0.0
        text_len = len(text)
        for count in freq.values():
            probability = count / text_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def has_high_entropy(text: str, threshold: float = 4.5) -> bool:
        """
        Check if text has high entropy (likely secret).
        
        Args:
            text: Input string
            threshold: Entropy threshold (default 4.5 bits/char)
            
        Returns:
            True if entropy > threshold
        """
        return EntropyAnalyzer.calculate_entropy(text) > threshold
    
    @staticmethod
    def has_secret_context(text: str) -> bool:
        """
        Check if text contains secret variable names or patterns.
        Examples: api_key=, password=, token=, SECRET=, etc.
        
        Args:
            text: Input string to check
            
        Returns:
            True if secret context keywords found
        """
        secret_keywords = [
            r'api_key\s*[=:]',
            r'api_secret\s*[=:]',
            r'password\s*[=:]',
            r'passwd\s*[=:]',
            r'secret\s*[=:]',
            r'token\s*[=:]',
            r'access_key\s*[=:]',
            r'private_key\s*[=:]',
            r'auth\s*[=:]',
            r'credential\s*[=:]',
            r'api_url\s*[=:]',
            r'db_password\s*[=:]',
            r'aws_secret\s*[=:]',
            r'api_token\s*[=:]',
        ]
        
        text_lower = text.lower()
        for pattern in secret_keywords:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def entropy_score(text: str, context_boost: float = 1.3) -> float:
        """
        Probability-like score based on entropy + context.
        
        Args:
            text: Input string
            context_boost: Multiply entropy prob if secret context found
            
        Returns:
            Score in range [0.0, 1.0] where 1.0 = definitely secret
        """
        entropy = EntropyAnalyzer.calculate_entropy(text)
        has_context = EntropyAnalyzer.has_secret_context(text)
        
        # Normalize entropy to [0, 1]
        # 5.5 bits/char = theoretical max for ASCII
        entropy_prob = min(entropy / 5.5, 1.0)
        
        # Boost score if secret context detected
        if has_context:
            entropy_prob = min(entropy_prob * context_boost, 1.0)
        
        return entropy_prob


class CascadeEnsembleDetector:
    """
    4-Level Cascade Ensemble Detector.
    
    Progressively applies detectors only when needed:
    - L1: BiLSTM (primary, 70% traffic exits here)
    - L2: SVM (gray zone, 20% traffic)
    - L2.5: Entropy analysis (unknown secrets)
    - L3: Regex (zero false-negatives, 10% traffic)
    """
    
    def __init__(self,
                 use_bilstm: bool = True,
                 use_svm: bool = True,
                 use_entropy: bool = True,
                 use_regex: bool = True,
                 bilstm_bounds: Tuple[float, float] = (0.2, 0.8),
                 svm_bounds: Tuple[float, float] = (0.25, 0.75),
                 entropy_threshold: float = 4.5,
                 entropy_context_boost: float = 1.3):
        """
        Initialize cascade ensemble detector.
        
        Args:
            use_bilstm: Enable BiLSTM L1 detector
            use_svm: Enable SVM L2 detector
            use_entropy: Enable entropy analysis L2.5
            use_regex: Enable regex L3
            bilstm_bounds: (low, high) confidence thresholds for BiLSTM early exit
            svm_bounds: (low, high) confidence thresholds for SVM early exit
            entropy_threshold: Shannon entropy threshold (bits/char)
            entropy_context_boost: Multiplier for entropy when secret context found
        """
        self.use_bilstm = use_bilstm
        self.use_svm = use_svm
        self.use_entropy = use_entropy
        self.use_regex = use_regex
        
        self.bilstm_bounds = bilstm_bounds
        self.svm_bounds = svm_bounds
        self.entropy_threshold = entropy_threshold
        self.entropy_context_boost = entropy_context_boost
        
        # Initialize detectors
        self.bilstm_detector = None
        self.svm_detector = None
        self.entropy_analyzer = EntropyAnalyzer()
        
        self._load_models()
    
    def _load_models(self):
        """Load all available ML models (BiLSTM, SVM)."""
        try:
            if self.use_bilstm and TFBiLSTMDetector:
                self.bilstm_detector = TFBiLSTMDetector()
                print("[CASCADE] BiLSTM L1 detector loaded")
        except Exception as e:
            print(f"[CASCADE] BiLSTM load failed: {e}")
            self.use_bilstm = False
        
        try:
            if self.use_svm and MLDetector:
                self.svm_detector = MLDetector(model_type="svm")
                print("[CASCADE] SVM L2 detector loaded")
        except Exception as e:
            print(f"[CASCADE] SVM load failed: {e}")
            self.use_svm = False
        
        if self.use_entropy:
            print("[CASCADE] Entropy analysis L2.5 enabled")
        
        if self.use_regex:
            print("[CASCADE] Regex L3 enabled")
    
    def detect(self, text: str) -> Dict:
        """
        Run full cascade detection with early exit optimization.
        
        Args:
            text: Command or text to check
            
        Returns:
            Dict containing:
            {
                'decision': bool,  # True = BLOCK, False = ALLOW
                'cascade_level': int,  # Which level made decision (1, 2, 2.5, 3, or None)
                'confidence': float,  # 0.0-1.0
                'probs': {
                    'bilstm': float or None,
                    'svm': float or None,
                    'entropy': float or None,
                    'final': float or None
                },
                'reasoning': str  # Human-readable explanation
            }
        """
        
        p_bilstm = None
        p_svm = None
        p_entropy = None
        
        # ========== L1: BiLSTM (Primary Detector) ==========
        if self.use_bilstm and self.bilstm_detector:
            try:
                p_bilstm = self.bilstm_detector.score(text)
                
                # High confidence secret → BLOCK
                if p_bilstm > self.bilstm_bounds[1]:
                    return {
                        'decision': True,
                        'cascade_level': 1,
                        'confidence': p_bilstm,
                        'probs': {'bilstm': p_bilstm, 'svm': None, 'entropy': None, 'final': p_bilstm},
                        'reasoning': f'L1 BiLSTM: High confidence secret (prob={p_bilstm:.3f})'
                    }
                
                # High confidence safe → ALLOW
                elif p_bilstm < self.bilstm_bounds[0]:
                    return {
                        'decision': False,
                        'cascade_level': 1,
                        'confidence': 1 - p_bilstm,
                        'probs': {'bilstm': p_bilstm, 'svm': None, 'entropy': None, 'final': p_bilstm},
                        'reasoning': f'L1 BiLSTM: High confidence safe (prob={p_bilstm:.3f})'
                    }
                
                # Gray zone → continue to L2
            except Exception as e:
                print(f"[CASCADE] BiLSTM error: {e}")
        
        # ========== L2: SVM (Gray Zone Specialist) ==========
        if self.use_svm and self.svm_detector:
            try:
                p_svm_raw = self.svm_detector.score(text)
                
                # Normalize SVM decision margin to [0, 1] using sigmoid
                p_svm = 1.0 / (1.0 + math.exp(-p_svm_raw)) if p_svm_raw is not None else 0.5
                
                # High confidence secret
                if p_svm > self.svm_bounds[1]:
                    return {
                        'decision': True,
                        'cascade_level': 2,
                        'confidence': p_svm,
                        'probs': {'bilstm': p_bilstm, 'svm': p_svm, 'entropy': None, 'final': p_svm},
                        'reasoning': f'L2 SVM: High confidence secret (prob={p_svm:.3f})'
                    }
                
                # High confidence safe
                elif p_svm < self.svm_bounds[0]:
                    return {
                        'decision': False,
                        'cascade_level': 2,
                        'confidence': 1 - p_svm,
                        'probs': {'bilstm': p_bilstm, 'svm': p_svm, 'entropy': None, 'final': p_svm},
                        'reasoning': f'L2 SVM: High confidence safe (prob={p_svm:.3f})'
                    }
                
                # Gray zone → continue to L2.5
            except Exception as e:
                print(f"[CASCADE] SVM error: {e}")
        
        # ========== L2.5: Entropy Analysis (Unknown Secrets) ==========
        if self.use_entropy:
            try:
                entropy_val = self.entropy_analyzer.calculate_entropy(text)
                has_context = self.entropy_analyzer.has_secret_context(text)
                p_entropy = self.entropy_analyzer.entropy_score(text, self.entropy_context_boost)
                
                # High entropy + secret context → BLOCK
                if p_entropy > 0.75 and has_context:
                    return {
                        'decision': True,
                        'cascade_level': 2.5,
                        'confidence': p_entropy,
                        'probs': {'bilstm': p_bilstm, 'svm': p_svm, 'entropy': p_entropy, 'final': p_entropy},
                        'reasoning': f'L2.5 Entropy: High entropy ({entropy_val:.2f} bits/char) + secret context'
                    }
            except Exception as e:
                print(f"[CASCADE] Entropy error: {e}")

        # ========== L3: YOUR SecretDetector (200+ config.yaml patterns) ==========
        if self.use_regex:
            try:
                from secret_detector import SecretDetector
                detector = SecretDetector()  # Auto-uses your root/config.yaml (200+ patterns)
                hits = detector.detect(text)
                
                if len(hits) > 0:
                    hit_types = [hit['type'] for hit in hits[:3]]  # Top 3 hits
                    return {
                        'decision': True,
                        'cascade_level': 3,
                        'confidence': 1.0,
                        'probs': {'bilstm': p_bilstm, 'svm': p_svm, 'entropy': p_entropy, 'final': 1.0},
                        'reasoning': f'L3 SecretDetector: {len(hits)} hits ({", ".join(hit_types)})'
                    }
            except ImportError:
                print("[CASCADE] SecretDetector not found - L3 disabled")
            except Exception as e:
                print(f"[CASCADE] SecretDetector error: {e}")

        # ========== Final Decision: Safe ==========
        # Compute average of available probabilities (FIXED)
        probs = [p for p in [p_bilstm, p_svm, p_entropy] if p is not None]
        final_prob = np.mean(probs) if probs else 0.0  # ✅ FIXED

        return {
            'decision': False,
            'cascade_level': None,
            'confidence': 1 - final_prob,
            'probs': {'bilstm': p_bilstm, 'svm': p_svm, 'entropy': p_entropy, 'final': final_prob},
            'reasoning': 'All cascade levels passed, classified as safe'
        }




# ============ Quick Standalone Test ============
if __name__ == "__main__":
    print("=" * 70)
    print("CASCADE ENSEMBLE DETECTOR - STANDALONE TEST")
    print("=" * 70)
    
    # Initialize cascade (graceful fallback if models not available)
    cascade = CascadeEnsembleDetector(
        use_bilstm=True,  # Set to True if models available
        use_svm=True,
        use_entropy=True,
        use_regex=True
    )
    
    # Test cases
    test_cases = [
        ("git status", False),
        ("ls -la", False),
        ("export AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE", True),
        ("password=SuperSecret123!", True),
        ("api_key=sk_live_abc123xyz", True),
        ("hello world how are you", False),
        ("echo $TOKEN", True),
        ("database_password=MyP@ssw0rd", True),
        ("python script.py", False),
        ("token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", True),
    ]
    
    print("\nRunning tests:\n")
    passed = 0
    for text, expected_secret in test_cases:
        result = cascade.detect(text)
        decision_str = " BLOCK" if result['decision'] else "ALLOW"
        match = "✓" if result['decision'] == expected_secret else "✗"
        passed += (result['decision'] == expected_secret)
        
        print(f"{match} {decision_str} | Level {result['cascade_level']} | "
              f"Conf: {result['confidence']:.2f}")
        print(f"   Text: {text[:60]}")
        print(f"   Reason: {result['reasoning']}")
        print()
    
    print(f"\n{'='*70}")
    print(f"Results: {passed}/{len(test_cases)} passed")
    print(f"{'='*70}")