'use strict';

angular.module('mgcrea.ngStrap.tab', [])

  .provider('$tab', function() {

    var defaults = this.defaults = {
      animation: 'am-fade',
      template: 'tab/tab.tpl.html',
      navCl***REMOVED***: 'nav-tabs',
      activeCl***REMOVED***: 'active'
    };

    var controller = this.controller = function($scope, $element, $attrs) {
      var self = this;

      // Attributes options
      self.$options = angular.copy(defaults);
      angular.forEach(['animation', 'navCl***REMOVED***', 'activeCl***REMOVED***'], function(key) {
        if(angular.isDefined($attrs[key])) self.$options[key] = $attrs[key];
      });

      // Publish options on scope
      $scope.$navCl***REMOVED*** = self.$options.navCl***REMOVED***;
      $scope.$activeCl***REMOVED*** = self.$options.activeCl***REMOVED***;

      self.$panes = $scope.$panes = [];

      // DEPRECATED: $viewChangeListeners, please use $activePaneChangeListeners
      // Because we deprecated ngModel usage, we rename viewChangeListeners to 
      // activePaneChangeListeners to make more sense.
      self.$activePaneChangeListeners = self.$viewChangeListeners = [];

      self.$push = function(pane) {
        self.$panes.push(pane);
      };

      self.$remove = function(pane) {
        var index = self.$panes.indexOf(pane);
        var activeIndex = self.$panes.$active;

        // remove pane from $panes array
        self.$panes.splice(index, 1);

        if (index < activeIndex) {
          // we removed a pane before the active pane, so we need to 
          // decrement the active pane index
          activeIndex--;
        }
        else if (index === activeIndex && activeIndex === self.$panes.length) {
          // we remove the active pane and it was the one at the end,
          // so select the previous one
          activeIndex--;
        }
        self.$setActive(activeIndex);
      };

      self.$panes.$active = 0;
      self.$setActive = $scope.$setActive = function(value) {
        self.$panes.$active = value;
        self.$activePaneChangeListeners.forEach(function(fn) {
          fn();
        });
      };

    };

    this.$get = function() {
      var $tab = {};
      $tab.defaults = defaults;
      $tab.controller = controller;
      return $tab;
    };

  })

  .directive('bsTabs', function($window, $animate, $tab, $parse) {

    var defaults = $tab.defaults;

    return {
      require: ['?ngModel', 'bsTabs'],
      transclude: true,
      scope: true,
      controller: ['$scope', '$element', '$attrs', $tab.controller],
      templateUrl: function(element, attr) {
        return attr.template || defaults.template;
      },
      link: function postLink(scope, element, attrs, controllers) {

        var ngModelCtrl = controllers[0];
        var bsTabsCtrl = controllers[1];

        // DEPRECATED: ngModel, please use bsActivePane
        // 'ngModel' is deprecated bacause if interferes with form validation
        // and status, so avoid using it here.
        if(ngModelCtrl) {
          console.warn('Usage of ngModel is deprecated, please use bsActivePane instead!');

          // Update the modelValue following
          bsTabsCtrl.$activePaneChangeListeners.push(function() {
            ngModelCtrl.$setViewValue(bsTabsCtrl.$panes.$active);
          });

          // modelValue -> $formatters -> viewValue
          ngModelCtrl.$formatters.push(function(modelValue) {
            // console.warn('$formatter("%s"): modelValue=%o (%o)', element.attr('ng-model'), modelValue, typeof modelValue);
            bsTabsCtrl.$setActive(modelValue * 1);
            return modelValue;
          });

        }

        if (attrs.bsActivePane) {
          // adapted from angularjs ngModelController bindings
          // https://github.com/angular/angular.js/blob/v1.3.1/src%2Fng%2Fdirective%2Finput.js#L1730
          var parsedBsActivePane = $parse(attrs.bsActivePane);

          // Update bsActivePane value with change
          bsTabsCtrl.$activePaneChangeListeners.push(function() {
            parsedBsActivePane.***REMOVED***ign(scope, bsTabsCtrl.$panes.$active);
          });

          // watch bsActivePane for value changes
          scope.$watch(attrs.bsActivePane, function(newValue, oldValue) {
            bsTabsCtrl.$setActive(newValue * 1);
          }, true);
        }
      }
    };

  })

  .directive('bsPane', function($window, $animate, $sce) {

    return {
      require: ['^?ngModel', '^bsTabs'],
      scope: true,
      link: function postLink(scope, element, attrs, controllers) {

        var ngModelCtrl = controllers[0];
        var bsTabsCtrl = controllers[1];

        // Add base cl***REMOVED***
        element.addCl***REMOVED***('tab-pane');

        // Observe title attribute for change
        attrs.$observe('title', function(newValue, oldValue) {
          scope.title = $sce.trustAsHtml(newValue);
        });

        // Add animation cl***REMOVED***
        if(bsTabsCtrl.$options.animation) {
          element.addCl***REMOVED***(bsTabsCtrl.$options.animation);
        }

        attrs.$observe('disabled', function(newValue, oldValue) {
          scope.disabled = scope.$eval(newValue);
        });

        // Push pane to parent bsTabs controller
        bsTabsCtrl.$push(scope);

        // remove pane from tab controller when pane is destroyed
        scope.$on('$destroy', function() {
          bsTabsCtrl.$remove(scope);
        });

        function render() {
          var index = bsTabsCtrl.$panes.indexOf(scope);
          var active = bsTabsCtrl.$panes.$active;
          $animate[index === active ? 'addCl***REMOVED***' : 'removeCl***REMOVED***'](element, bsTabsCtrl.$options.activeCl***REMOVED***);
        }

        bsTabsCtrl.$activePaneChangeListeners.push(function() {
          render();
        });
        render();

      }
    };

  });
