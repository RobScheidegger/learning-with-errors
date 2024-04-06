from abc import ABC, abstractmethod
from typing import TypeVar

Message = TypeVar("Message")
Ciphertext = TypeVar("Ciphertext")
SecretKey = TypeVar("SecretKey")
PublicKey = TypeVar("PublicKey")
SchemeParameters = TypeVar("SchemeParameters")


class HomomorphicEncryptionScheme(ABC):
    """
    Abstract class for a generic homomorphic encryption scheme.
    """
    
    @abstractmethod
    def encrypt(self, k_p: PublicKey, m: Message) -> Ciphertext:
        """
        Encrypts a message.
        """
        pass
    
    @abstractmethod
    def decrypt(self, k_s: SecretKey, c: Ciphertext) -> Message:
        """
        Decrypts a message.
        """
        pass
    
    @abstractmethod
    def add(self, c_1: Ciphertext, c_2: Ciphertext) -> Message:
        """
        Adds two ciphertexts.
        """
        pass
    