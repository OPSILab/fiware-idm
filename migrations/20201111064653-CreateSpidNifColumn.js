module.exports = {
  up: (queryInterface, Sequelize) => {
    return queryInterface.addColumn('spid_credentials', 'organization_nif', {
      type:
        Sequelize.STRING(255) +
        (queryInterface.sequelize.dialect === 'mysql'
          ? ' CHARSET utf8mb4 COLLATE utf8mb4_unicode_ci'
          : ''),
      validate: { notEmpty: { msg: 'organization_url' } },
    });
  },

  down: (queryInterface, Sequelize) => {
    return queryInterface.removeColumn('spid_credentials', 'organization_nif');
  },
};
