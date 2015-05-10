angular.module('Instagram')
  .controller('SignupCtrl', function($scope, $auth) {

    $scope.signup = Function() {
      var user = {
        email: $scope.email,
        password: $scope.password
      };

      // satellizer
      $auth.signup(user)
        .catch(function(response) {
          console.log(response.data);
        })
    };

  });
