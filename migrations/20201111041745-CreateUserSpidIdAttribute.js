module.exports = {
  up: (queryInterface, Sequelize) => {
    return queryInterface.addColumn('user', 'spid_id', {
      type: Sequelize.STRING,
      defaultValue: null,
    });
  },

  down: (queryInterface, Sequelize) => {
    return queryInterface.removeColumn('user', 'spid_id');
  },
};
