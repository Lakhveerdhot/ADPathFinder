from adpathfinder.core.engine import ADPathFinderEngine


class ADPathFinderController:
    """
    Controls the ADPathFinder application workflow.
    """

    def __init__(self, config, logger):

        self.config = config

        self.logger = logger

        self.engine = ADPathFinderEngine(
            config=config,
            logger=logger
        )

    def run(self):

        self.logger.info("Controller started")

        self.engine.start()

        self.logger.info("Controller execution completed")

    def shutdown(self):

        self.engine.shutdown()