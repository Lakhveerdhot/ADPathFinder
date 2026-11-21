from datetime import datetime
import uuid


class Finding:

    def __init__(
        self,
        title,
        description,
        severity,
        affected_object,
        recommendation,
        category
    ):

        self.id = str(uuid.uuid4())[:8]

        self.title = title

        self.description = description

        self.severity = severity

        self.affected_object = affected_object

        self.recommendation = recommendation

        self.category = category

        self.created_at = datetime.now().isoformat()

    def to_dict(self):

        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "affected_object": self.affected_object,
            "recommendation": self.recommendation,
            "category": self.category,
            "created_at": self.created_at
        }