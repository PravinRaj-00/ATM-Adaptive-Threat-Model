class ConfirmationError(Exception):
    pass


class ConfirmationGuard:
    """
    Validates confirmation requirements for sensitive exposure stages.
    Does not handle user input collection — only validation.
    """

    CONFIRMATION_PHRASES = {
        "typed_phrase": "I UNDERSTAND THIS EXPOSES MY SEED",
        "typed_phrase_plus_tier_check": "I ACCEPT FULL RESPONSIBILITY FOR KEY EXPOSURE",
    }

    def validate(self, confirmation_type: str, user_input: str | None = None):
        """
        Validates confirmation requirement.

        confirmation_type:
            - "none"
            - "simple_confirmation"
            - "typed_phrase"
            - "typed_phrase_plus_tier_check"
        """

        if confirmation_type == "none":
            return True

        if confirmation_type == "simple_confirmation":
            if user_input and user_input.lower() == "yes":
                return True
            raise ConfirmationError("Simple confirmation failed.")

        if confirmation_type in self.CONFIRMATION_PHRASES:
            required_phrase = self.CONFIRMATION_PHRASES[confirmation_type]
            if user_input == required_phrase:
                return True
            raise ConfirmationError("Typed confirmation phrase incorrect.")

        raise ConfirmationError("Unknown confirmation type.")
    
